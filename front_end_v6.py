import subprocess
import sys
import json
import datetime
import requests
import base64
import io
import pandas as pd
import plotly.express as px
import dash
from dash import dcc, html, Input, Output, State, callback, ALL, no_update, ctx
import dash_mantine_components as dmc
from dash_iconify import DashIconify

# [필수 패키지 확인]
_REQUIRED = {"dash": "dash", "dash_mantine_components": "dash-mantine-components",
             "dash_iconify": "dash-iconify", "pandas": "pandas", "plotly": "plotly",
             "requests": "requests", "deep_translator": "deep-translator"}
for mod, pkg in _REQUIRED.items():
    try: __import__(mod)
    except ImportError: subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

from deep_translator import GoogleTranslator

_translation_cache = {}

def translate_to_korean(text):
    if not text or not str(text).strip():
        return text
    if text in _translation_cache:
        return _translation_cache[text]          
    try:
        translated = GoogleTranslator(source="auto", target="ko").translate(str(text)[:4900])
        result = translated or text
    except Exception:
        result = text                             
    _translation_cache[text] = result
    return result

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# [디자인 및 색상 정의]
THEME_BG_MAIN = "#0a192f"      
THEME_BG_PAPER = "#112240"     
THEME_BORDER = "#233554"       
THEME_TEXT_ACCENT = "#64ffda"  
THEME_TEXT_MAIN = "#ccd6f6"

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff944d",
    "MEDIUM": "#ffd11a",
    "LOW": "#4da6ff",
    "UNKNOWN": "#a6a6a6"
}

# [레이아웃]
app.layout = dmc.MantineProvider(
    forceColorScheme="dark",
    children=[
        html.Div(
            style={"backgroundColor": THEME_BG_MAIN, "minHeight": "100vh", "color": THEME_TEXT_MAIN, "padding": "20px"},
            children=[
                dmc.LoadingOverlay(id="loading-overlay", visible=False, overlayProps={"blur": 2}, zIndex=1000),

                # 헤더
                dmc.Group(justify="space-between", mb="xl", children=[
                    dmc.Group([
                        DashIconify(icon="material-symbols:shield-lock", width=40, color=THEME_TEXT_ACCENT),
                        dmc.Title("DSP Integrated Security Dashboard", order=1, style={"color": THEME_TEXT_ACCENT}),
                        # [추가 5] 대시보드 설명 버튼 (물음표)
                        dmc.ActionIcon(
                            DashIconify(icon="tabler:help", width=24), 
                            id="btn-help", size="lg", variant="outline", color="teal", radius="xl",
                            title="대시보드 사용 가이드"
                        )
                    ]),
                    # [추가 2] PDF 추출 버튼 (기능은 향후 API 연동을 위해 UI만 생성)
                    dmc.Button("PDF 추출", id="btn-export-pdf", variant="outline", color="teal", leftSection=DashIconify(icon="tabler:file-download"))
                ]),

                dmc.Grid(children=[
                    # 왼쪽: 업로드 및 로그
                    dmc.GridCol(span=4, children=[
                        dmc.Paper(withBorder=True, p="md", radius="md", mb="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Text("이미지 분석 설정", fw=700, mb="md", style={"color": THEME_TEXT_ACCENT}),
                            dcc.Loading(id="loading-upload", type="circle", color=THEME_TEXT_ACCENT, children=[
                                dcc.Upload(
                                    id='upload-data',
                                    accept=".tar", # [추가 4] tar 확장자만 업로드 가능하도록 제한
                                    children=html.Div([
                                        DashIconify(id="upload-icon", icon="tabler:upload", width=30),
                                        dmc.Text("파일을 드래그하세요 (.tar 전용)", id="upload-text")
                                    ], style={"textAlign": "center"}),
                                    style={'width': '100%', 'height': '100px', 'borderWidth': '2px', 'borderStyle': 'dashed', 'borderColor': THEME_BORDER, 'borderRadius': '8px', 'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center', 'cursor': 'pointer'}
                                )
                            ]),
                            dmc.Space(h=15),
                            dmc.Button("스캔 시작", id="btn-start-scan", fullWidth=True, color="teal")
                        ]),
                        # 실시간 시스템 로그
                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Text("시스템 진행 로그", fw=700, mb="xs", style={"color": THEME_TEXT_ACCENT}),
                            html.Div(id="system-log-container", style={"height": "200px", "overflowY": "auto", "fontSize": "12px"})
                        ])
                    ]),

                    # 오른쪽: 원형 그래프
                    dmc.GridCol(span=8, children=[
                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Group(justify="space-between", mb="md", children=[
                                dmc.Text("취약점 분포 (심각도)", fw=700, style={"color": THEME_TEXT_ACCENT}),
                                dmc.SegmentedControl(
                                    id="pie-tool-filter-toggle",
                                    # [추가 3] 미스매치 필터 추가
                                    data=[{"label": "전체", "value": "ALL"}, {"label": "Trivy", "value": "trivy"}, {"label": "Grype", "value": "grype"}, {"label": "미스매치", "value": "mismatch"}],
                                    value="ALL",
                                    size="sm"
                                )
                            ]),
                            html.Div(
                                style={"position": "relative", "width": "100%", "height": "100%"},
                                children=[
                                    dcc.Graph(id="severity-pie-chart", style={"height": "100%"}, config={'displaylogo': False, 'modeBarButtonsToRemove': ['toImage']}),
                                    html.Div(
                                        id="pie-center-text",
                                        title="클릭하여 전체 심각도 보기 (필터 해제)",
                                        style={
                                            "position": "absolute", "top": "45%", "left": "50%",
                                            "transform": "translate(-50%, -50%)", "cursor": "pointer",
                                            "textAlign": "center", "zIndex": 10,
                                            "display": "flex", "flexDirection": "column", "justifyContent": "center", "alignItems": "center",
                                            "width": "130px", "height": "130px", "borderRadius": "50%"
                                        }
                                    )
                                ]
                            )
                        ])
                    ])
                ]),

                dmc.Space(h="xl"),

                # 결과 테이블 및 다중 필터 섹션
                dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                    dmc.Group(justify="space-between", mb="md", children=[
                        dmc.Text("취약점 상세 리스트", fw=700, style={"color": THEME_TEXT_ACCENT}),
                        dmc.Group([
                            dmc.SegmentedControl(
                                id="tool-filter-toggle",
                                # [추가 3] 미스매치 필터 추가
                                data=[{"label": "전체", "value": "ALL"}, {"label": "Trivy", "value": "trivy"}, {"label": "Grype", "value": "grype"}, {"label": "미스매치", "value": "mismatch"}],
                                value="ALL"
                            ),
                            dmc.SegmentedControl(
                                id="class-filter-toggle",
                                data=[{"label": "전체", "value": "ALL"}, {"label": "APP", "value": "APP"}, {"label": "OS", "value": "OS"}, {"label": "Secret", "value": "SECRET"}],
                                value="ALL"
                            )
                        ], gap="sm")
                    ]),
                    html.Div(id="vulnerability-table-container", style={"maxHeight": "500px", "overflowY": "auto"})
                ]),

                dcc.Store(id="analysis-result-store"),
                dcc.Store(id="upload-log-store"),
                dcc.Store(id="selected-severity-store", data=None), 
                dcc.Store(id="current-vuln-id", data=None),
                dcc.Store(id="sort-state", data={"column": "id", "ascending": True}), 
                dcc.Store(id="scan-status-store", data="idle"), 

                # 상세 분석 모달
                dmc.Modal(
                    id="detail-modal", title="취약점 상세 분석 결과", size="xl",
                    children=[
                        dmc.Group(justify="flex-end", mb="sm", children=[
                            dmc.SegmentedControl(id="lang-toggle", data=[{"label": "English", "value": "EN"}, {"label": "한국어", "value": "KR"}], value="EN")
                        ]),
                        html.Div(id="modal-content")
                    ],
                    styles={"content": {"backgroundColor": THEME_BG_PAPER}}
                ),
                
                # [추가 5] 도움말 모달
                dmc.Modal(
                    id="help-modal", title="💡 대시보드 사용 가이드", size="lg", centered=True,
                    children=[
                        dmc.Stack([
                            dmc.Text("1. 이미지 분석 설정", fw=700, color=THEME_TEXT_ACCENT),
                            dmc.Text("• 확장자가 .tar 인 Docker 이미지 파일만 업로드할 수 있습니다.", size="sm"),
                            dmc.Text("• 파일을 드래그 앤 드롭한 후, '스캔 시작' 버튼을 눌러야 분석이 진행됩니다.", size="sm"),
                            
                            dmc.Divider(),
                            dmc.Text("2. 취약점 분포 및 필터링", fw=700, color=THEME_TEXT_ACCENT),
                            dmc.Text("• Trivy, Grype 개별 탐지 결과 또는 두 도구의 심각도가 엇갈린 '미스매치' 결과를 선택해 볼 수 있습니다.", size="sm"),
                            dmc.Text("• 원형 차트의 조각(예: CRITICAL)을 클릭하면 하단 테이블이 해당 위험도로 자동 필터링됩니다. 정중앙 숫자를 누르면 필터가 해제됩니다.", size="sm"),
                            
                            dmc.Divider(),
                            dmc.Text("3. 상세 리스트 확인", fw=700, color=THEME_TEXT_ACCENT),
                            dmc.Text("• 테이블 우측의 눈동자 아이콘을 클릭하면 취약점의 세부 설명과 해결 패치 버전을 확인할 수 있습니다.", size="sm"),
                            dmc.Text("• 상세보기 창에서 한국어/영어 번역 기능을 지원합니다.", size="sm")
                        ])
                    ],
                    styles={"content": {"backgroundColor": THEME_BG_PAPER, "color": THEME_TEXT_MAIN}}
                )
            ]
        )
    ]
)

# [콜백 함수]

@callback(
    Output("upload-text", "children"),
    Input("upload-data", "contents"),
    State("upload-data", "filename"),
    prevent_initial_call=True
)
def show_uploaded_file(contents, filename):
    if contents and filename:
        return f"업로드됨: {filename}  —  '스캔 시작' 클릭"
    return no_update

# [개선 1] 파일 안 넣고 스캔 눌렀을 때 무한 로딩 및 스캐너 동작 방지
@callback(
    Output("upload-log-store", "data", allow_duplicate=True),
    Output("scan-status-store", "data", allow_duplicate=True),
    Output("loading-overlay", "visible", allow_duplicate=True),
    Output("btn-start-scan", "disabled", allow_duplicate=True),
    Input("btn-start-scan", "n_clicks"),
    State("upload-data", "contents"), # contents(파일) 확인 추가
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    prevent_initial_call=True
)
def trigger_scan_log(n_clicks, contents, filename, current_logs):
    # 파일이 업로드되지 않았으면 스캔 로직을 트리거하지 않고 튕겨냅니다.
    if not n_clicks or not contents: 
        return no_update, no_update, no_update, no_update
        
    logs = current_logs or []
    
    logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"파일 업로드 확인 완료: {filename}"})
    logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": "API 서버로 전송 준비 중..."})
    logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": "분석 요청 전송 중 (Target: Trivy & Grype)..."})
    
    return logs, "trigger", True, True

@callback(
    Output("analysis-result-store", "data"),
    Output("upload-log-store", "data"),
    Output("scan-status-store", "data"),
    Output("loading-overlay", "visible"),
    Output("btn-start-scan", "disabled"),
    Input("scan-status-store", "data"),
    State("upload-data", "contents"),
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    prevent_initial_call=True
)
def perform_scan(status, contents, filename, current_logs):
    if status != "trigger" or not contents:
        return no_update, no_update, no_update, no_update, no_update
    
    logs = current_logs or []
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        
        response = requests.post(
            "http://127.0.0.1:8000/scan",
            files={'file': (filename, io.BytesIO(decoded), 'application/x-tar')},
            data={'user_id': 'admin'},
            timeout=1800
        )
        
        if response.status_code == 200:
            scan_data = response.json()
            logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": "스캐너 분석 완료 — DB 적재 확인 중..."})

            job_id = scan_data.get("job_id")
            final_data = scan_data  
            if job_id:
                try:
                    db_resp = requests.get(f"http://127.0.0.1:3000/results/{job_id}", timeout=60)
                    if db_resp.status_code == 200:
                        final_data = db_resp.json()
                        vuln_cnt = len(final_data.get("vulnerabilities", []))
                        logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"DB 결과 조회 완료 (API 경유 · 취약점 {vuln_cnt}건)"})
                    else:
                        logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"DB 조회 실패({db_resp.status_code}) — 스캐너 응답으로 대체"})
                except Exception as db_err:
                    logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"DB 조회 통신 장애 — 스캐너 응답으로 대체: {str(db_err)[:80]}"})
            else:
                logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": "job_id 미수신 — 스캐너 응답을 그대로 사용"})

            return final_data, logs, "idle", False, False
        else:
            logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"서버 에러 발생: {response.status_code}"})
            return no_update, logs, "idle", False, False
    except Exception as e:
        logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": f"통신 장애 발생: {str(e)}"})
        return no_update, logs, "idle", False, False

@callback(
    Output("severity-pie-chart", "figure"),
    Output("pie-center-text", "children"),
    Input("analysis-result-store", "data"),
    Input("pie-tool-filter-toggle", "value")
)
def update_pie_chart(data, tool_filter):
    def get_empty_state(msg="데이터 없음"):
        fig = px.pie(title=msg, hole=0.4).update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        fig.update_traces(domain=dict(x=[0, 1], y=[0, 1]))
        center = [html.Div("0건", style={"fontSize": "24px", "fontWeight": "bold", "color": THEME_TEXT_ACCENT})]
        return fig, center

    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return get_empty_state()

    df = pd.DataFrame(data["vulnerabilities"])
    if df.empty or 'severity' not in df.columns:
        return get_empty_state()

    # [추가 3] 미스매치 처리: vulnerability_id 기준으로 다른 위험도가 잡히면 미스매치로 판정
    if tool_filter == "mismatch":
        dup_ids = df.groupby('vulnerability_id')['severity'].nunique()
        mismatch_vids = dup_ids[dup_ids > 1].index
        df = df[df['vulnerability_id'].isin(mismatch_vids)]
        if df.empty: return get_empty_state("미스매치 결과 없음")
    elif tool_filter != "ALL":
        df = df[df['source'] == tool_filter]
        if df.empty: return get_empty_state(f"{tool_filter.upper()} 결과 없음")

    total_count = len(df)
    counts = df['severity'].value_counts().reset_index()
    counts.columns = ['severity', 'count']

    fig = px.pie(
        counts, values='count', names='severity',
        color='severity', color_discrete_map=SEVERITY_COLORS,
        hole=0.4
    )
    
    fig.update_traces(
        domain=dict(x=[0, 1], y=[0, 1]),
        hovertemplate="<b>%{label}</b><br>탐지 수: %{value}건", 
        textinfo='label+percent'
    )
    
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.05),
        paper_bgcolor="rgba(0,0,0,0)", 
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=THEME_TEXT_MAIN), 
        margin=dict(t=5, b=5, l=5, r=5)
    )
    
    center_html = [
        html.Div(f"{total_count}건", style={"fontSize": "24px", "fontWeight": "bold", "color": THEME_TEXT_ACCENT})
    ]
    
    return fig, center_html

@callback(
    Output("selected-severity-store", "data"),
    Input("severity-pie-chart", "clickData"),
    Input("pie-center-text", "n_clicks"),
    prevent_initial_call=True
)
def manage_severity_filter(click_data, center_clicks):
    trigger = ctx.triggered_id
    if trigger == "pie-center-text":
        return None
    elif trigger == "severity-pie-chart" and click_data:
        return click_data['points'][0]['label']
    return no_update

@callback(
    Output("vulnerability-table-container", "children"),
    Output("sort-state", "data"),
    Input("analysis-result-store", "data"),
    Input("tool-filter-toggle", "value"),
    Input("class-filter-toggle", "value"),
    Input("selected-severity-store", "data"),
    Input({"type": "sort-btn", "index": ALL}, "n_clicks"), 
    State("sort-state", "data")
)
def update_table(data, tool_filter, class_filter, selected_severity, sort_clicks, sort_state):
    sort_state = sort_state or {"column": "id", "ascending": True}
    
    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return dmc.Text("분석 결과가 없습니다.", c="dimmed", ta="center", py=50), sort_state

    df = pd.DataFrame(data["vulnerabilities"])
    if df.empty:
        return dmc.Text("분석 결과가 없습니다.", c="dimmed", ta="center", py=50), sort_state

    if ctx.triggered_id and isinstance(ctx.triggered_id, dict) and ctx.triggered_id.get("type") == "sort-btn":
        if sort_clicks and any(sort_clicks):
            clicked_col = ctx.triggered_id["index"]
            if sort_state.get("column") == clicked_col:
                sort_state["ascending"] = not sort_state.get("ascending", True)
            else:
                sort_state["column"] = clicked_col
                sort_state["ascending"] = True

    if selected_severity:
        df = df[df['severity'] == selected_severity]
    
    # [추가 3] 미스매치 필터링 로직 (테이블 용)
    if tool_filter == "mismatch":
        dup_ids = df.groupby('vulnerability_id')['severity'].nunique()
        mismatch_vids = dup_ids[dup_ids > 1].index
        df = df[df['vulnerability_id'].isin(mismatch_vids)]
    elif tool_filter != "ALL":
        df = df[df['source'] == tool_filter]

    if class_filter != "ALL":
        OS_PKG_TYPES = {'deb', 'dpkg', 'rpm', 'apk', 'apkg', 'portage', 'alpm', 'nix'}
        OS_DISTROS   = {'debian', 'ubuntu', 'alpine', 'centos', 'redhat', 'amazon',
                        'amzn', 'oracle', 'photon', 'suse', 'rocky', 'alma', 'fedora'}

        def classify_row(row):
            rc = str(row.get('result_class', '')).lower()
            rt = str(row.get('result_type', '')).lower()
            if 'secret' in rc or 'secret' in rt:
                return 'SECRET'
            if rc == 'os-pkgs':
                return 'OS'                                  
            if rc == 'lang-pkgs':
                return 'APP'                                 
            if rt in OS_PKG_TYPES or rt in OS_DISTROS:
                return 'OS'                                  
            return 'APP'

        df['_computed_category'] = df.apply(classify_row, axis=1)
        df = df[df['_computed_category'] == class_filter]

    if sort_state.get("column") == "severity" and "severity" in df.columns:
        severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        df['_sev_rank'] = df['severity'].map(severity_map).fillna(5)
        df = df.sort_values(by=["_sev_rank", "vulnerability_id"], ascending=[sort_state["ascending"], True])
        df = df.drop(columns=['_sev_rank'])
    elif "vulnerability_id" in df.columns:
        df = df.sort_values(by="vulnerability_id", ascending=sort_state["ascending"])

    id_icon = " ▲" if sort_state.get("column") == "id" and sort_state["ascending"] else (" ▼" if sort_state.get("column") == "id" else "")
    sev_icon = " ▲" if sort_state.get("column") == "severity" and sort_state["ascending"] else (" ▼" if sort_state.get("column") == "severity" else "")
    
    header = html.Thead(
        html.Tr([
            html.Th(
                html.Div([f"ID{id_icon}"], id={"type": "sort-btn", "index": "id"}, 
                         style={"cursor": "pointer", "userSelect": "none", "color": THEME_TEXT_ACCENT}), 
                style={"textAlign": "center"}
            ),
            html.Th("패키지", style={"textAlign": "center"}),
            html.Th(
                html.Div([f"심각도{sev_icon}"], id={"type": "sort-btn", "index": "severity"}, 
                         style={"cursor": "pointer", "userSelect": "none", "color": THEME_TEXT_ACCENT}), 
                style={"textAlign": "center"}
            ),
            html.Th("도구", style={"textAlign": "center"}),
            html.Th("고정 여부", style={"textAlign": "center"}),
            html.Th("상세", style={"textAlign": "center"})
        ]),
        style={"position": "sticky", "top": 0, "backgroundColor": THEME_BG_PAPER, "zIndex": 10}
    )
    
    rows = []
    for _, row in df.iterrows():
        sev_color = SEVERITY_COLORS.get(row['severity'], "#fff")
        rows.append(html.Tr([
            html.Td(row['vulnerability_id'], style={"textAlign": "center"}),
            html.Td(row['package_name'], style={"textAlign": "center"}),
            html.Td(dmc.Badge(row['severity'], color=sev_color, variant="filled"), style={"textAlign": "center"}),
            html.Td(row['source'].upper(), style={"textAlign": "center"}),
            html.Td("Available" if row['is_fixed_available'] else "-", style={"textAlign": "center"}),
            html.Td(
                dmc.Center(
                    dmc.ActionIcon(DashIconify(icon="mdi:eye"), id={"type": "view-detail", "index": row['vulnerability_id']}, variant="subtle")
                ), 
                style={"textAlign": "center"}
            )
        ]))
    
    table = dmc.Table(children=[header, html.Tbody(rows)], withColumnBorders=True, highlightOnHover=True)
    return table, sort_state

@callback(
    Output("detail-modal", "opened"),
    Output("modal-content", "children"),
    Output("current-vuln-id", "data"),
    Input({"type": "view-detail", "index": ALL}, "n_clicks"),
    Input("lang-toggle", "value"),
    State("analysis-result-store", "data"),
    State("current-vuln-id", "data"),
    prevent_initial_call=True
)
def open_modal(n_clicks, lang, data, current_id):
    if not ctx.triggered or not data or not data.get("vulnerabilities"): 
        return no_update, no_update, no_update
    
    trigger_id = ctx.triggered_id
    triggered_val = ctx.triggered[0]['value']

    if isinstance(trigger_id, dict) and trigger_id.get("type") == "view-detail":
        if not triggered_val:
            return False, no_update, no_update
        vuln_id = trigger_id["index"]
        is_open = True
    elif trigger_id == "lang-toggle":
        if current_id is None:
            return False, no_update, no_update
        vuln_id = current_id
        is_open = no_update 
    else:
        return no_update, no_update, no_update

    v = next((item for item in data["vulnerabilities"] if item["vulnerability_id"] == vuln_id), None)
    if not v:
        return no_update, no_update, no_update
    
    description = v.get('description', 'No Description')
    title_val   = v.get('title', 'No Title')
    if lang == "KR":
        description = translate_to_korean(description)
        title_val   = translate_to_korean(title_val)
    display_desc = description

    fields = [
        ("Source", v['source']), ("Target", v.get('target','-')), ("Class", v.get('result_class','-')),
        ("Type", v.get('result_type','-')), ("Vulnerability ID", v['vulnerability_id']),
        ("Package", v['package_name']), ("Path", v.get('package_path','-')),
        ("Installed", v['installed_version']), ("Fixed", v.get('fixed_version','-')),
        ("Fix Available", str(v['is_fixed_available'])), ("Severity", v['severity']),
        ("Primary URL", html.A(v['primary_url'], href=v['primary_url'], target="_blank", style={"color": THEME_TEXT_ACCENT}) if v.get('primary_url') else "-"),
        ("Title", title_val)
    ]

    content = dmc.Stack([
        dmc.Text(f"상세 정보: {vuln_id}", fw=700, size="lg", style={"color": THEME_TEXT_ACCENT}),
        dmc.Grid([
            dmc.GridCol([dmc.Text(label, fw=600, size="sm", c="dimmed"), dmc.Text(str(val), size="md")], span=4)
            for label, val in fields
        ]),
        dmc.Divider(label="Description"),
        dmc.Text(display_desc, size="sm", style={"lineHeight": "1.6"})
    ], gap="md")
    
    return is_open, content, vuln_id

# [추가 5] 도움말 모달 작동 콜백
@callback(
    Output("help-modal", "opened"),
    Input("btn-help", "n_clicks"),
    prevent_initial_call=True
)
def open_help(n_clicks):
    if n_clicks:
        return True
    return no_update

@callback(Output("system-log-container", "children"), Input("upload-log-store", "data"))
def render_logs(logs):
    if not logs: return dmc.Text("로그가 없습니다.", c="dimmed")
    return [html.Div(f"[{l['time']}] {l['content']}", style={"marginBottom": "4px"}) for l in logs]

if __name__ == "__main__":
    app.run(debug=False, port=8050)