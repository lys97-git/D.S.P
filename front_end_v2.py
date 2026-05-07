import subprocess
import sys

# [필수 라이브러리 설치 확인]
REQUIRED_PACKAGES = ["json", "datetime", "requests", "webbrowser", "threading", 
                     "pandas", "plotly", "dash", "dash-mantine-components", 
                     "dash-iconify", "base64", "io"]

def install_and_import():
    for package in REQUIRED_PACKAGES:
        try:
            import_name = package.replace("-", "_")
            __import__(import_name)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install_and_import()

import json
import datetime
import requests  # API 통신용
import webbrowser
from threading import Timer
import pandas as pd
import plotly.express as px
import dash
from dash import dcc, html, Input, Output, State, callback, ALL, no_update, ctx
import dash_mantine_components as dmc
from dash_iconify import DashIconify
import base64
import io


# [통합 설정]
# scanner_2.py가 실행 중인 주소 (기본 8000 포트)
SCANNER_API_URL = "http://127.0.0.1:8000/scan" 

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# [컬럼명 통일 정의] - PDF 명세서 기준
# vulnerability_id, pkg_name, severity, pkg_path, installed_version, fixed_version, description

# [UI 레이아웃]
app.layout = dmc.MantineProvider(
    id="mantine-provider",
    forceColorScheme="light",
    children=[
        dcc.Store(id='analysis-result-store'), # 분석 결과 저장소
        dcc.Store(id='upload-log-store', data=[]),
        
# [수정됨] 부모 컨테이너를 relative로 설정
        html.Div(
            style={"position": "relative"},
            children=[
                # 전체 화면 로딩 오버레이 (children을 빼고 독립적으로 배치)
                dmc.LoadingOverlay(
                    id="loading-overlay", # 콜백 연동을 위해 ID 추가
                    visible=False,        # 기본적으로는 숨김 상태
                    loaderProps={"type": "bars", "color": "blue", "size": "xl"},
                    overlayProps={"radius": "sm", "blur": 2},
                    zIndex=1000
                ),
                
                # 메인 콘텐츠 (LoadingOverlay와 같은 위치(형제 레벨)에 배치)
                html.Div(
                    id="main-content",
                    style={"padding": "20px"},
                    children=[
                        dmc.Container(
                            size="xl",
                            children=[
                                # 헤더 섹션
                                dmc.Group(
                                    justify="space-between", mb="lg",
                                    children=[
                                        dmc.Group([
                                            DashIconify(icon="tabler:shield-check", width=35, color="#228be6"),
                                            dmc.Title("Project WH: Integrated Security Dashboard", order=2)
                                        ]),
                                        dmc.Button("PDF 저장", id="btn-pdf", variant="outline", leftSection=DashIconify(icon="tabler:file-download"))
                                    ]
                                ),

                                # 업로드 섹션
                                dmc.Paper(
                                    withBorder=True, shadow="sm", radius="md", p="md", mb="xl",
                                    children=[
                                        dmc.Text("이미지 파일 업로드 (image.tar)", fw=700, mb="md"),
                                        dcc.Upload(
                                            id='upload-data', multiple=False,
                                            children=html.Div([
                                                DashIconify(icon="tabler:upload", width=30),
                                                dmc.Text("클릭하거나 파일을 드래그하세요.")
                                            ]),
                                            style={
                                                'width': '100%', 'height': '100px', 'borderWidth': '2px',
                                                'borderStyle': 'dashed', 'borderColor': '#ced4da', 'borderRadius': '8px',
                                                'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center', 'cursor': 'pointer'
                                            }
                                        )
                                    ]
                                ),

                                # 메인 대시보드 그리드
                                dmc.Grid(
                                    gutter="lg",
                                    children=[
                                        # 섹션 1: 위험도 차트
                                        dmc.GridCol(
                                            dmc.Paper(id="sec-1", withBorder=True, p="xl", radius="md", mih=350), 
                                            span=6
                                        ),
                                        # 섹션 2: 필터링 상세 리스트
                                        dmc.GridCol(
                                            dmc.Paper(id="sec-2", withBorder=True, p="xl", radius="md", mih=350), 
                                            span=6
                                        ),
                                        # 섹션 3: 라이선스/통계 (추후 확장)
                                        dmc.GridCol(id="sec-3", span=6),
                                        # 섹션 4: 분석 로그
                                        dmc.GridCol(id="sec-4", span=6),
                                    ]
                                )
                            ]
                        )
                    ]
                )
            ]
        ),
        # 상세 정보 모달
        dmc.Modal(
            id="detail-modal", title="취약점 상세 정보", centered=True, size="lg",
            children=[html.Div(id="modal-content")]
        )
    ]
)

# [콜백 1: 파일 업로드 및 API 연동]
@callback(
    Output("analysis-result-store", "data"),
    Output("upload-log-store", "data"),
    Output("loading-overlay", "visible"), 
    Input("upload-data", "contents"),
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    prevent_initial_call=True
)
def update_output(contents, filename, current_logs):
    if contents is None:
        return no_update, no_update, False

    # 1. 기존 로그가 비어있으면 빈 리스트로 초기화
    if current_logs is None:
        current_logs = []

    # 현재 시간 문자열 생성
    now_str = datetime.datetime.now().strftime("%H:%M:%S")

    try:
        # 2. Dash 업로드 데이터(Base64) 디코딩
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)

        # 3. 백엔드로 보낼 파일 객체 포장
        files = {
            'file': (filename, io.BytesIO(decoded), 'application/x-tar')
        }

        # 4. 백엔드 통신 (스캐너 모듈 호출)
        response = requests.post("http://127.0.0.1:8000/scan", files=files)

        if response.status_code == 200:
            # --- 통신 성공! ---
            # 로그 내용 정의 및 updated_logs 변수 생성
            success_log = {"time": now_str, "content": f"[{filename}] 분석이 성공적으로 완료되었습니다."}
            updated_logs = [success_log] + current_logs
            
            # 리턴값: (가공된 결과, 업데이트된 로그, 로딩창 끄기)
            return response.json(), updated_logs, False
            
        else:
            # --- 통신 실패 (서버 에러 등) ---
            error_log = {"time": now_str, "content": f"서버 에러 발생: {response.status_code}"}
            updated_logs = [error_log] + current_logs
            print(f"백엔드 에러: {response.text}")
            
            return no_update, updated_logs, False

    except Exception as e:
        # --- 프론트엔드/네트워크 내부 에러 ---
        except_log = {"time": now_str, "content": f"통신 장애 발생: {str(e)}"}
        updated_logs = [except_log] + current_logs
        print(f"프론트엔드 에러: {e}")
        
        return no_update, updated_logs, False

# [콜백 2: 데이터 시각화 (섹션 1, 2, 4)]
@callback(
    Output("sec-1", "children"),
    Output("sec-2", "children"),
    Output("sec-4", "children"),
    Input("analysis-result-store", "data"),
    Input("upload-log-store", "data")
)
def update_visuals(scan_result, log_data):
    # 1. 섹션 4 (로그)
    log_rows = [html.Tr([html.Td(l["time"]), html.Td(l["content"])]) for l in log_data]
    sec4 = dmc.Stack([
        dmc.Text("섹션 4: 분석 로그", fw=700),
        dmc.Table(striped=True, children=[html.Tbody(log_rows)])
    ])

    if not scan_result:
        return dmc.Text("파일을 업로드하면 차트가 표시됩니다.", c="dimmed", ta="center", mt=100), no_update, sec4

    # 2. 섹션 1 (Radial/Pie Chart) - 컬럼명: severity
    summary = scan_result["summary"]
    df = pd.DataFrame([{"severity": k, "count": v} for k, v in summary.items()])
    fig = px.pie(df, names="severity", values="count", hole=0.5,
                 color="severity", color_discrete_map={"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "blue"})
    fig.update_layout(margin=dict(l=0, r=0, t=0, b=0), showlegend=True)
    
    sec1 = dmc.Stack([
        dmc.Text("섹션 1: 위험도 분포", fw=700),
        dcc.Graph(figure=fig, style={"height": "280px"})
    ])

    # 3. 섹션 2 (상세 리스트) - 통일된 컬럼명 사용
    vulns = scan_result["vulnerabilities"]
    rows = [
        html.Tr(
            id={"type": "vuln-row", "index": v["vulnerability_id"]},
            style={"cursor": "pointer"},
            children=[
                html.Td(v["vulnerability_id"]),
                html.Td(v["pkg_name"]),
                html.Td(dmc.Badge(v["severity"], color="red" if v["severity"] == "Critical" else "orange"))
            ]
        ) for v in vulns
    ]
    
    sec2 = dmc.Stack([
        dmc.Text("섹션 2: 상세 취약점 리스트", fw=700),
        dmc.Table(highlightOnHover=True, children=[
            html.Thead(html.Tr([html.Th("ID"), html.Th("패키지"), html.Th("위험도")])),
            html.Tbody(rows)
        ])
    ])

    return sec1, sec2, sec4

# [콜백 3: 모달 상세 정보]
@callback(
    Output("detail-modal", "opened"),
    Output("modal-content", "children"),
    Input({"type": "vuln-row", "index": ALL}, "n_clicks"),
    State("analysis-result-store", "data"),
    prevent_initial_call=True
)
def open_modal(n_clicks, scan_result):
    if not any(n_clicks) or not scan_result: return False, no_update
    
    clicked_id = ctx.triggered_id["index"]
    v = next(item for item in scan_result["vulnerabilities"] if item["vulnerability_id"] == clicked_id)
    
    content = dmc.Stack([
        dmc.Grid([
            dmc.GridCol(dmc.Text("패키지명", fw=600), span=4), dmc.GridCol(dmc.Text(v["pkg_name"]), span=8),
            dmc.GridCol(dmc.Text("설치 경로", fw=600), span=4), dmc.GridCol(dmc.Text(v["pkg_path"], size="sm"), span=8),
            dmc.GridCol(dmc.Text("설치 버전", fw=600), span=4), dmc.GridCol(dmc.Text(v["installed_version"]), span=8),
            dmc.GridCol(dmc.Text("해결 버전", fw=600), span=4), dmc.GridCol(dmc.Text(v["fixed_version"], c="blue", fw=700), span=8),
        ]),
        dmc.Divider(),
        dmc.Text("취약점 설명", fw=600),
        dmc.Text(v["description"], size="sm")
    ])
    return True, content

# [브라우저 자동 실행 및 앱 실행]
def open_browser():
    webbrowser.open_new("http://127.0.0.1:8050/")

if __name__ == "__main__":
    Timer(1.5, open_browser).start()
    app.run(debug=False, port=8050)