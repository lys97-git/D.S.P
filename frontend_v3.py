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
import requests
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

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# 🎨 [네이비 테마 색상 정의]
THEME_BG_MAIN = "#0a192f"      
THEME_BG_PAPER = "#112240"     
THEME_BORDER = "#233554"       
THEME_TEXT_MAIN = "#ccd6f6"    
THEME_TEXT_ACCENT = "#64ffda"  

card_style = {
    "backgroundColor": THEME_BG_PAPER, 
    "borderColor": THEME_BORDER, 
    "color": THEME_TEXT_MAIN
}

# [UI 레이아웃]
app.layout = dmc.MantineProvider(
    id="mantine-provider",
    forceColorScheme="dark", 
    children=[
        dcc.Store(id='analysis-result-store'),
        dcc.Store(id='upload-log-store', data=[]),
        dcc.Store(id='recent-files-store', data=[]), 
        
        html.Div(
            style={"position": "relative", "backgroundColor": THEME_BG_MAIN, "minHeight": "100vh"},
            children=[
                dmc.LoadingOverlay(
                    id="loading-overlay",
                    visible=False,
                    loaderProps={"type": "bars", "color": THEME_TEXT_ACCENT, "size": "xl"},
                    overlayProps={"radius": "sm", "blur": 2, "color": THEME_BG_MAIN},
                    zIndex=1000
                ),
                
                html.Div(
                    id="main-content",
                    style={"padding": "30px"},
                    children=[
                        dmc.Container(
                            size="xl",
                            children=[
                                # 헤더
                                dmc.Group(
                                    justify="space-between", mb="xl",
                                    children=[
                                        dmc.Group([
                                            DashIconify(icon="tabler:shield-check", width=35, color=THEME_TEXT_ACCENT),
                                            dmc.Title("Project WH: Security Dashboard", order=2, style={"color": THEME_TEXT_MAIN})
                                        ]),
                                        dmc.Button("PDF 저장", id="btn-pdf", variant="outline", color="teal", leftSection=DashIconify(icon="tabler:file-download"))
                                    ]
                                ),

                                # 업로드 및 조작 패널
                                dmc.Paper(
                                    withBorder=True, shadow="md", radius="md", p="lg", mb="xl",
                                    style=card_style,
                                    children=[
                                        dmc.Text("이미지 파일 업로드 (image.tar)", fw=700, mb="md", style={"color": THEME_TEXT_ACCENT}),
                                        dcc.Loading(
                                            id="loading-upload",
                                            type="circle", # 로딩 스피너 모양 (circle, dot, default 등)
                                            color=THEME_TEXT_ACCENT, # 민트색
                                            children=[
                                                dcc.Upload(
                                                    id='upload-data', multiple=False,
                                                    children=html.Div([
                                                        DashIconify(id="upload-icon", icon="tabler:upload", width=30, style={"marginBottom": "10px"}),
                                                        html.Br(),
                                                        dmc.Text("클릭하거나 파일을 드래그하세요.", id="upload-text", style={"color": THEME_TEXT_MAIN})
                                                    ], style={"textAlign": "center"}),
                                                    style={
                                                        'width': '100%', 'height': '120px', 'borderWidth': '2px',
                                                        'borderStyle': 'dashed', 'borderColor': THEME_BORDER, 'borderRadius': '8px',
                                                        'display': 'flex', 'flexDirection': 'column', 'alignItems': 'center', 'justifyContent': 'center', 'cursor': 'pointer',
                                                        'backgroundColor': "#0f172a"
                                                    }
                                                )
                                            ]
                                        ),
                                        
                                        # 도구 선택 및 버튼
                                        dmc.Group(
                                            justify="space-between", mt="md",
                                            children=[
                                                dmc.Group([
                                                    dmc.Text("스캔 도구 선택:", size="sm", fw=600, style={"color": THEME_TEXT_MAIN}),
                                                    dmc.SegmentedControl(
                                                        id="scan-tool-select",
                                                        value="trivy+grype",
                                                        data=[
                                                            {"label": "Trivy", "value": "trivy"},
                                                            {"label": "Grype", "value": "grype"},
                                                            {"label": "Trivy + Grype", "value": "trivy+grype"},
                                                        ],
                                                        color="teal"
                                                    )
                                                ]),
                                                dmc.Button(
                                                    "스캔 시작", id="btn-start-scan", variant="filled", color="teal",
                                                    leftSection=DashIconify(icon="tabler:player-play")
                                                )
                                            ]
                                        )
                                    ]
                                ),

                                # 대시보드 4분할 그리드
                                dmc.Grid(
                                    gutter="lg",
                                    children=[
                                        dmc.GridCol(dmc.Paper(id="sec-1", withBorder=True, p="xl", radius="md", mih=350, style=card_style), span=6),
                                        dmc.GridCol(dmc.Paper(id="sec-2", withBorder=True, p="xl", radius="md", mih=350, style=card_style), span=6),
                                        dmc.GridCol(dmc.Paper(id="sec-3", withBorder=True, p="xl", radius="md", mih=350, style=card_style), span=6),
                                        dmc.GridCol(dmc.Paper(id="sec-4", withBorder=True, p="xl", radius="md", mih=350, style=card_style), span=6),
                                    ]
                                )
                            ]
                        )
                    ]
                )
            ]
        ),
        dmc.Modal(
            id="detail-modal", title="취약점 상세 정보", centered=True, size="lg",
            styles={"header": {"backgroundColor": THEME_BG_PAPER}, "body": {"backgroundColor": THEME_BG_PAPER, "color": THEME_TEXT_MAIN}},
            children=[html.Div(id="modal-content")]
        )
    ]
)

# [콜백 0: 파일 업로드 감지]
@callback(
    Output("upload-text", "children"),
    Output("upload-text", "style"),
    Output("upload-icon", "style"),
    Input("upload-data", "contents"), 
    State("upload-data", "filename"),
    prevent_initial_call=True
)
def update_upload_text(contents, filename):
    if contents and filename:
        return (
            f"✅ 대기 중인 파일: {filename} (도구 선택 후 우측 '스캔 시작' 클릭)", 
            {"color": THEME_TEXT_ACCENT, "fontWeight": "bold"},
            {"display": "none"} 
        )
    return no_update, no_update, no_update

# [콜백 1: 스캔 시작 버튼 클릭 감지 -> 백엔드 통신 및 로딩 상태 자동 제어]
@callback(
    Output("analysis-result-store", "data"),
    Output("upload-log-store", "data"),
    Output("recent-files-store", "data"), 
    Input("btn-start-scan", "n_clicks"),          
    State("upload-data", "contents"),             
    State("upload-data", "filename"),
    State("scan-tool-select", "value"),           
    State("upload-log-store", "data"),
    State("recent-files-store", "data"),
    
    running=[
        (Output("loading-overlay", "visible"), True, False),
        (Output("btn-start-scan", "disabled"), True, False),
        (Output("upload-text", "children"), "⏳ 파일을 분석하고 있습니다. 잠시만 기다려주세요...", "✅ 분석 완료! (새 파일을 올리려면 다시 드래그하세요)"), # 상태 텍스트 변경
        (Output("upload-text", "style"), {"color": "#ffcc00", "fontWeight": "bold"}, {"color": THEME_TEXT_ACCENT, "fontWeight": "bold"}) # 글자색 노란색으로 변경
    ],
    prevent_initial_call=True
)
def run_scan(n_clicks, contents, filename, scan_tool, current_logs, current_recent):
    # 버튼을 누르지 않았거나 파일이 없으면 무시
    if not n_clicks or not contents:
        return no_update, no_update, no_update

    current_logs = current_logs or []
    current_recent = current_recent or []
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)

        files = {'file': (filename, io.BytesIO(decoded), 'application/x-tar')}
        data = {'user_id': 'admin_user', 'scan_name': 'dashboard_scan', 'scan_tool': scan_tool}
        
        response = requests.post("http://127.0.0.1:8000/scan", files=files, data=data)

        if response.status_code == 200:
            success_log = {"time": now_str, "content": f"[{filename}] 분석 완료 (도구: {scan_tool.upper()})"}
            recent_file_record = {"filename": filename, "date": date_str, "tool": scan_tool}
            return response.json(), [success_log] + current_logs, [recent_file_record] + current_recent
        else:
            error_log = {"time": now_str, "content": f"서버 에러 발생: {response.status_code}"}
            recent_file_record = {"filename": filename, "date": date_str, "tool": f"{scan_tool} (실패)"}
            return no_update, [error_log] + current_logs, [recent_file_record] + current_recent

    except Exception as e:
        except_log = {"time": now_str, "content": f"통신 장애 발생: {str(e)}"}
        recent_file_record = {"filename": filename, "date": date_str, "tool": f"{scan_tool} (통신장애)"}
        return no_update, [except_log] + current_logs, [recent_file_record] + current_recent


# [콜백 2: 시각화 데이터 화면에 뿌리기]
@callback(
    Output("sec-1", "children"),
    Output("sec-2", "children"),
    Output("sec-3", "children"), 
    Output("sec-4", "children"),
    Input("analysis-result-store", "data"),
    Input("upload-log-store", "data"),
    Input("recent-files-store", "data") 
)
def update_visuals(scan_result, log_data, recent_files):
    log_rows = [html.Tr([html.Td(l["time"]), html.Td(l["content"])]) for l in log_data]
    sec4 = dmc.Stack([
        dmc.Text("섹션 4: 실시간 시스템 로그", fw=700, style={"color": THEME_TEXT_ACCENT}),
        html.Div(style={"maxHeight": "280px", "overflowY": "auto"}, children=[
            dmc.Table(striped=True, children=[html.Tbody(log_rows)], style={"color": THEME_TEXT_MAIN})
        ])
    ])

    recent_rows = [
        html.Tr([
            html.Td(f["filename"]), html.Td(f["date"]), 
            html.Td(dmc.Badge(f["tool"].upper(), color="red" if "실패" in f["tool"] or "장애" in f["tool"] else "teal", variant="light"))
        ]) for f in recent_files
    ]
    sec3 = dmc.Stack([
        dmc.Text("섹션 3: 최근 분석 파일 목록", fw=700, style={"color": THEME_TEXT_ACCENT}),
        html.Div(style={"maxHeight": "280px", "overflowY": "auto"}, children=[
            dmc.Table(striped=True, children=[
                html.Thead(html.Tr([html.Th("파일명"), html.Th("분석 일시"), html.Th("스캔 도구")])),
                html.Tbody(recent_rows)
            ], style={"color": THEME_TEXT_MAIN})
        ])
    ])

    if not scan_result:
        empty_msg = dmc.Center(dmc.Text("파일을 업로드하면 데이터가 표시됩니다.", c="dimmed"), style={"height": "250px"})
        return dmc.Stack([dmc.Text("섹션 1: 위험도 분포", fw=700, style={"color": THEME_TEXT_ACCENT}), empty_msg]), \
               dmc.Stack([dmc.Text("섹션 2: 상세 취약점 리스트", fw=700, style={"color": THEME_TEXT_ACCENT}), empty_msg]), \
               sec3, sec4

    summary = scan_result["summary"]
    df = pd.DataFrame([{"severity": k, "count": v} for k, v in summary.items()])
    fig = px.pie(df, names="severity", values="count", hole=0.6,
                 color="severity", color_discrete_map={"Critical": "#ff4d4f", "High": "#ff9c6e", "Medium": "#ffd666", "Low": "#69c0ff"})
    fig.update_layout(margin=dict(l=0, r=0, t=0, b=0), showlegend=True, 
                      paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color=THEME_TEXT_MAIN))
    
    sec1 = dmc.Stack([
        dmc.Text("섹션 1: 위험도별 분포", fw=700, style={"color": THEME_TEXT_ACCENT}),
        dcc.Graph(figure=fig, style={"height": "280px"})
    ])

    vulns = scan_result["vulnerabilities"]
    rows = [
        html.Tr(
            id={"type": "vuln-row", "index": v["vulnerability_id"]},
            style={"cursor": "pointer"},
            children=[
                html.Td(v["vulnerability_id"]), html.Td(v["pkg_name"]),
                html.Td(dmc.Badge(v["severity"], color="red" if v["severity"] == "Critical" else "orange", variant="filled"))
            ]
        ) for v in vulns
    ]
    
    sec2 = dmc.Stack([
        dmc.Text("섹션 2: 필터링된 취약점 내역", fw=700, style={"color": THEME_TEXT_ACCENT}),
        html.Div(style={"maxHeight": "280px", "overflowY": "auto"}, children=[
            dmc.Table(highlightOnHover=True, children=[
                html.Thead(html.Tr([html.Th("ID"), html.Th("패키지"), html.Th("위험도")])),
                html.Tbody(rows)
            ], style={"color": THEME_TEXT_MAIN})
        ])
    ])

    return sec1, sec2, sec3, sec4


# [콜백 3: 모달]
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
            dmc.GridCol(dmc.Text("패키지명", fw=600, style={"color": THEME_TEXT_ACCENT}), span=4), dmc.GridCol(dmc.Text(v["pkg_name"]), span=8),
            dmc.GridCol(dmc.Text("설치 경로", fw=600, style={"color": THEME_TEXT_ACCENT}), span=4), dmc.GridCol(dmc.Text(v["pkg_path"], size="sm"), span=8),
            dmc.GridCol(dmc.Text("설치 버전", fw=600, style={"color": THEME_TEXT_ACCENT}), span=4), dmc.GridCol(dmc.Text(v["installed_version"]), span=8),
            dmc.GridCol(dmc.Text("해결 버전", fw=600, style={"color": THEME_TEXT_ACCENT}), span=4), dmc.GridCol(dmc.Text(v["fixed_version"], c="teal", fw=700), span=8),
        ]),
        dmc.Divider(color=THEME_BORDER),
        dmc.Text("취약점 설명", fw=600, style={"color": THEME_TEXT_ACCENT}),
        dmc.Text(v["description"], size="sm")
    ])
    return True, content

def open_browser():
    webbrowser.open_new("http://127.0.0.1:8050/")

if __name__ == "__main__":
    Timer(1.5, open_browser).start()
    app.run(debug=False, port=8050)