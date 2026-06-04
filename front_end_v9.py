# ================================================================
# DSP Integrated Security Dashboard — v7 (v6 + 로그인 통합)
# ================================================================

import subprocess
import sys
import os                                    
import json
import datetime
import base64
import io

# ================================================================
# [BOOTSTRAP] 사용자 라이브러리 import 이전에 의존성 확보 (PEP 668 대응)
# ================================================================
_REQUIRED = {
    "requests": "requests",
    "pandas": "pandas",
    "plotly": "plotly",
    "dash": "dash",
    "dash_mantine_components": "dash-mantine-components",
    "dash_iconify": "dash-iconify",
    "deep_translator": "deep-translator",
    "flask": "flask",                        
}

def _ensure_pkg(pkg):
    for extra in (["--break-system-packages"], ["--user"], []):
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", pkg, *extra],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return False

for _mod, _pkg in _REQUIRED.items():
    try:
        __import__(_mod)
    except ImportError:
        if not _ensure_pkg(_pkg):
            print(f"[BOOTSTRAP] '{_pkg}' 자동설치 실패 — 수동 설치 필요:", file=sys.stderr)
            print(f"  python3 -m pip install --break-system-packages {_pkg}", file=sys.stderr)

import requests
import pandas as pd
import plotly.express as px
import dash
from dash import dcc, html, Input, Output, State, callback, ALL, no_update, ctx
import dash_mantine_components as dmc
from dash_iconify import DashIconify
from flask import send_from_directory, redirect  
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

# ================================================================
# [LOGIN-INTEGRATION] 정적 서빙 및 인증 게이트
# ================================================================
server = app.server  
_LOGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login')

@server.route('/login')
def _serve_login_redirect():
    return redirect('/login/', code=302)

@server.route('/login/')
def _serve_login_index():
    return send_from_directory(_LOGIN_DIR, 'index.html')

@server.route('/login/<path:filename>')
def _serve_login_assets(filename):
    return send_from_directory(_LOGIN_DIR, filename)

app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <script>
            (function () {
                if (window.location.pathname.startsWith('/login')) return;
                const keys = Object.keys(window.localStorage)
                    .filter(k => k.startsWith('sb-') && k.endsWith('-auth-token'));
                let authed = false;
                for (const k of keys) {
                    try {
                        const v = JSON.parse(window.localStorage.getItem(k));
                        if (v && v.access_token && v.expires_at && v.expires_at * 1000 > Date.now()) {
                            authed = true;
                            break;
                        }
                    } catch (e) { }
                }
                if (!authed) {
                    window.location.replace('/login/');
                }
            })();
        </script>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# [디자인 및 색상 정의]
THEME_BG_MAIN = "#0a192f"
THEME_BG_PAPER = "#112240"
THEME_BORDER = "#233554"
THEME_TEXT_ACCENT = "#64ffda"
THEME_TEXT_MAIN = "#ccd6f6"
THEME_TEXT_DIMMED = "#8892b0"

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff944d",
    "MEDIUM": "#ffd11a",
    "LOW": "#4da6ff",
    "UNKNOWN": "#a6a6a6"
}

def create_title_with_popover(title_text, popover_content, position="right"):
    return dmc.Group(gap="xs", children=[
        dmc.Text(title_text, fw=700, style={"color": THEME_TEXT_ACCENT}),
        dmc.Popover(
            width=280, position=position, withArrow=True, shadow="md",
            children=[
                dmc.PopoverTarget(
                    dmc.ActionIcon(
                        DashIconify(icon="tabler:info-circle", width=18), 
                        size="sm", variant="transparent", color="teal"
                    )
                ),
                dmc.PopoverDropdown(
                    dmc.Text(popover_content, size="sm", style={"color": THEME_TEXT_MAIN}),
                    style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}
                )
            ]
        )
    ])

# [레이아웃]
app.layout = dmc.MantineProvider(
    forceColorScheme="dark",
    children=[
        html.Div(
            style={"backgroundColor": THEME_BG_MAIN, "minHeight": "100vh", "color": THEME_TEXT_MAIN, "padding": "20px"},
            children=[
                dmc.LoadingOverlay(id="loading-overlay", visible=False, overlayProps={"blur": 2}, zIndex=1000),

                # 🌟 [네비게이션 바 섹션] 🌟
                dmc.Paper(
                    withBorder=True, p="md", radius="md", mb="xl",
                    style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER},
                    children=[
                        dmc.Group(justify="space-between", children=[
                            # 좌측: 로고 및 메뉴 탭
                            dmc.Group(gap="xl", children=[
                                dmc.Group(gap="sm", children=[
                                    DashIconify(icon="material-symbols:shield-lock", width=36, color=THEME_TEXT_ACCENT),
                                    dmc.Title("DSP Integrated Security Dashboard", order=3, style={"color": THEME_TEXT_ACCENT}),
                                ]),
                                dmc.Group(gap="sm", children=[
                                    dmc.Button("이미지 분석", id="nav-image-btn", variant="light", color="teal", size="sm"),
                                    dmc.Button("동적분석", id="nav-dynamic-btn", variant="subtle", color="gray", size="sm"),
                                ])
                            ]),
                            # 우측: 로그인 정보, PDF, 로그아웃 (위치 고정)
                            dmc.Group([
                                dmc.Text(id="user-email-display", size="sm", c=THEME_TEXT_ACCENT, fw=600),
                                dmc.Button("PDF 추출", id="btn-export-pdf", variant="outline", color="teal", leftSection=DashIconify(icon="tabler:file-download")),
                                dmc.Button("로그아웃", id="btn-logout", variant="subtle", color="red", leftSection=DashIconify(icon="tabler:logout"))
                            ], gap="sm")
                        ])
                    ]
                ),

                # ──────────────────────────────────────────────────────────
                # 📌 1. 이미지 분석 페이지 (현재 작업 중인 페이지 내용)
                # ──────────────────────────────────────────────────────────
                html.Div(
                    id="page-image-analysis",
                    style={"display": "block"}, # 기본적으로 보이도록 설정
                    children=[
                        dmc.Grid(gutter="md", children=[
                            dmc.GridCol(span=4, style={"display": "flex", "flexDirection": "column"}, children=[
                                dmc.Paper(withBorder=True, p="md", radius="md", mb="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                                    create_title_with_popover("이미지 분석 설정", "확장자가 .tar 인 Docker 이미지 파일만 업로드할 수 있습니다. 파일을 박스에 넣은 후 '스캔 시작'을 누르세요."),
                                    dmc.Space(h="md"),
                                    dcc.Loading(id="loading-upload", type="circle", color=THEME_TEXT_ACCENT, children=[
                                        dcc.Upload(
                                            id='upload-data',
                                            accept=".tar",
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
                                dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER, "flex": 1, "display": "flex", "flexDirection": "column"}, children=[
                                    dmc.Text("시스템 진행 로그", fw=700, mb="xs", style={"color": THEME_TEXT_ACCENT}),
                                    html.Div(id="system-log-container", style={"flex": 1, "overflowY": "auto", "fontSize": "12px", "minHeight": "200px"})
                                ])
                            ]),

                            dmc.GridCol(span=8, style={"display": "flex"}, children=[
                                dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER, "width": "100%", "display": "flex", "flexDirection": "column"}, children=[
                                    dmc.Group(justify="space-between", mb="md", children=[
                                        create_title_with_popover("취약점 분포", "그래프의 조각(예: CRITICAL)을 클릭하면 아래 표가 해당 위험도로 자동 필터링됩니다. 해제하려면 정중앙 숫자를 누르세요.", position="bottom"),
                                        dmc.SegmentedControl(
                                            id="pie-tool-filter-toggle",
                                            data=[{"label": "전체", "value": "ALL"}, {"label": "Trivy", "value": "trivy"}, {"label": "Grype", "value": "grype"}],
                                            value="ALL",
                                            size="sm"
                                        )
                                    ]),
                                    html.Div(
                                        style={"position": "relative", "flex": 1, "minHeight": "400px"},
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

                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Group(justify="space-between", mb="md", children=[
                                create_title_with_popover("취약점 상세 리스트", "우측 끝의 눈동자 아이콘을 클릭하면 취약점의 세부 설명과 한국어 번역 기능을 이용할 수 있습니다."),
                                dmc.SegmentedControl(
                                    id="tool-filter-toggle",
                                    data=[{"label": "전체", "value": "ALL"}, {"label": "Trivy", "value": "trivy"}, {"label": "Grype", "value": "grype"}],
                                    value="ALL"
                                )
                            ]),
                            html.Div(id="vulnerability-table-container", style={"maxHeight": "500px", "overflowY": "auto"})
                        ]),
                        
                        dmc.Space(h="xl"),

                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Group(justify="space-between", mb="md", children=[
                                create_title_with_popover(
                                    "미스매치 분석 리스트", 
                                    "Trivy와 Grype 간에 서로 탐지된 심각도가 다르게 나타난 내역만 별도로 추출하여 비교합니다."
                                )
                            ]),
                            html.Div(id="mismatch-table-container", style={"maxHeight": "500px", "overflowY": "auto"})
                        ])
                    ]
                ),

                # ──────────────────────────────────────────────────────────
                # 📌 2. 동적 분석 페이지 (임시 준비 영역)
                # ──────────────────────────────────────────────────────────
                html.Div(
                    id="page-dynamic-analysis",
                    style={"display": "none"}, # 기본적으로 숨김 처리
                    children=[
                        dmc.Paper(
                            withBorder=True, p="xl", radius="md", ta="center", mt="100px",
                            style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER},
                            children=[
                                DashIconify(icon="tabler:activity", width=64, color=THEME_TEXT_DIMMED, style={"marginBottom": "20px"}),
                                dmc.Title("동적 분석 페이지", order=2, style={"color": THEME_TEXT_ACCENT}, mb="sm"),
                                dmc.Text("현재 이 기능은 준비 중입니다.", c="dimmed", size="lg")
                            ]
                        )
                    ]
                ),

                dcc.Location(id="url", refresh=False),
                dcc.Store(id="analysis-result-store"),
                dcc.Store(id="upload-log-store"),
                dcc.Store(id="selected-severity-store", data=None),
                dcc.Store(id="current-vuln-id", data=None),
                dcc.Store(id="sort-state", data={"column": "id", "ascending": True}),
                dcc.Store(id="scan-status-store", data="idle"),
                dcc.Store(id="pdf-url-store"),
                dcc.Store(id="auth-token-store"),  # 🌟 JWT 토큰 스토어                       
                html.Div(id="_logout-dummy", style={"display": "none"}),
                html.Div(id="_pdf-trigger-dummy", style={"display": "none"}),  

                dmc.Modal(
                    id="detail-modal", title="취약점 상세 분석 결과", size="xl",
                    children=[
                        dmc.Group(justify="flex-end", mb="sm", children=[
                            dmc.SegmentedControl(id="lang-toggle", data=[{"label": "English", "value": "EN"}, {"label": "한국어", "value": "KR"}], value="EN")
                        ]),
                        html.Div(id="modal-content")
                    ],
                    styles={"content": {"backgroundColor": THEME_BG_PAPER}}
                )
            ]
        )
    ]
)

# ================================================================
# [콜백 함수] - 네비게이션 메뉴 화면 전환 
# ================================================================
@callback(
    Output("page-image-analysis", "style"),
    Output("page-dynamic-analysis", "style"),
    Output("nav-image-btn", "variant"),
    Output("nav-image-btn", "color"),
    Output("nav-dynamic-btn", "variant"),
    Output("nav-dynamic-btn", "color"),
    Input("nav-image-btn", "n_clicks"),
    Input("nav-dynamic-btn", "n_clicks"),
    prevent_initial_call=True
)
def switch_pages(btn_image, btn_dynamic):
    trigger = ctx.triggered_id
    if trigger == "nav-dynamic-btn":
        # 동적분석 활성화, 이미지 숨김
        return {"display": "none"}, {"display": "block"}, "subtle", "gray", "light", "teal"
    else:
        # 이미지분석 활성화, 동적 숨김
        return {"display": "block"}, {"display": "none"}, "light", "teal", "subtle", "gray"

# ================================================================
# [콜백 함수] - 기존 로직
# ================================================================
@callback(
    Output("upload-text", "children"),
    Input("upload-data", "contents"),
    State("upload-data", "filename"),
    prevent_initial_call=True
)
def show_uploaded_file(contents, filename):
    if contents and filename:
        return [f"업로드됨: {filename}", html.Br(), " —  '스캔 시작' 클릭"]
    return no_update

@callback(
    Output("upload-log-store", "data", allow_duplicate=True),
    Output("scan-status-store", "data", allow_duplicate=True),
    Output("loading-overlay", "visible", allow_duplicate=True),
    Output("btn-start-scan", "disabled", allow_duplicate=True),
    Input("btn-start-scan", "n_clicks"),
    State("upload-data", "contents"),
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    prevent_initial_call=True
)
def trigger_scan_log(n_clicks, contents, filename, current_logs):
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
    State("auth-token-store", "data"),
    prevent_initial_call=True
)
def perform_scan(status, contents, filename, current_logs, token):
    if status != "trigger" or not contents:
        return no_update, no_update, no_update, no_update, no_update

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    logs = current_logs or []
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)

        response = requests.post(
            "http://127.0.0.1:8000/scan",
            files={'file': (filename, io.BytesIO(decoded), 'application/x-tar')},
            data={'user_id': 'admin'},
            headers=headers,
            timeout=1800
        )

        if response.status_code == 200:
            scan_data = response.json()
            logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": "스캐너 분석 완료 — DB 적재 확인 중..."})

            job_id = scan_data.get("job_id")
            final_data = scan_data
            if job_id:
                try:
                    db_resp = requests.get(f"http://127.0.0.1:3000/results/{job_id}", headers=headers, timeout=60)
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

    if tool_filter != "ALL":
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
    Input("selected-severity-store", "data"),
    Input({"type": "sort-btn", "index": ALL}, "n_clicks"),
    State("sort-state", "data")
)
def update_table(data, tool_filter, selected_severity, sort_clicks, sort_state):
    sort_state = sort_state or {"column": "id", "ascending": True}

    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return dmc.Text("분석 결과가 없습니다.", c="dimmed", ta="center", py=50), sort_state

    df = pd.DataFrame(data["vulnerabilities"])
    if df.empty:
        return dmc.Text("분석 결과가 없습니다.", c="dimmed", ta="center", py=50), sort_state

    OS_PKG_TYPES = {'deb', 'dpkg', 'rpm', 'apk', 'apkg', 'portage', 'alpm', 'nix'}
    OS_DISTROS   = {'debian', 'ubuntu', 'alpine', 'centos', 'redhat', 'amazon',
                    'amzn', 'oracle', 'photon', 'suse', 'rocky', 'alma', 'fedora'}

    def classify_row(row):
        rc = str(row.get('result_class', '')).lower()
        rt = str(row.get('result_type', '')).lower()
        if 'secret' in rc or 'secret' in rt: return 'SECRET'
        if rc == 'os-pkgs': return 'OS'
        if rc == 'lang-pkgs': return 'APP'
        if rt in OS_PKG_TYPES or rt in OS_DISTROS: return 'OS'
        return 'APP'

    df['class'] = df.apply(classify_row, axis=1)

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

    if tool_filter != "ALL":
        df = df[df['source'] == tool_filter]

    if sort_state.get("column") == "severity" and "severity" in df.columns:
        severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        df['_sev_rank'] = df['severity'].map(severity_map).fillna(5)
        df = df.sort_values(by=["_sev_rank", "vulnerability_id"], ascending=[sort_state["ascending"], True])
        df = df.drop(columns=['_sev_rank'])
    elif sort_state.get("column") == "class":
        df = df.sort_values(by=["class", "vulnerability_id"], ascending=[sort_state["ascending"], True])
    elif "vulnerability_id" in df.columns:
        df = df.sort_values(by="vulnerability_id", ascending=sort_state["ascending"])

    id_icon = " ▲" if sort_state.get("column") == "id" and sort_state["ascending"] else (" ▼" if sort_state.get("column") == "id" else "")
    class_icon = " ▲" if sort_state.get("column") == "class" and sort_state["ascending"] else (" ▼" if sort_state.get("column") == "class" else "")
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
                html.Div([f"클래스{class_icon}"], id={"type": "sort-btn", "index": "class"},
                         style={"cursor": "pointer", "userSelect": "none", "color": THEME_TEXT_ACCENT}),
                style={"textAlign": "center"}
            ),
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
            html.Td(row['class'], style={"textAlign": "center", "fontWeight": 600}),
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
    Output("mismatch-table-container", "children"),
    Input("analysis-result-store", "data")
)
def update_mismatch_table(data):
    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return dmc.Text("미스매치 분석 결과가 없습니다.", c="dimmed", ta="center", py=50)

    df = pd.DataFrame(data["vulnerabilities"])
    if df.empty:
        return dmc.Text("미스매치 분석 결과가 없습니다.", c="dimmed", ta="center", py=50)

    mismatch_vids = {m.get("vulnerability_id") for m in (data.get("mismatch_meta") or [])}
    if not mismatch_vids:
        dup_ids = df.groupby('vulnerability_id')['severity'].nunique()
        mismatch_vids = dup_ids[dup_ids > 1].index

    df_mis = df[df['vulnerability_id'].isin(mismatch_vids)]
    if df_mis.empty:
        return dmc.Text("분석된 미스매치 내역이 없습니다.", c="dimmed", ta="center", py=50)

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    rows = []
    for vid, group in df_mis.groupby('vulnerability_id'):
        group = group.copy()
        group['_rank'] = group['severity'].map(severity_rank).fillna(5)
        group_sorted = group.sort_values(by='_rank')

        higher = group_sorted.iloc[0]
        lower = group_sorted.iloc[-1]

        high_element = dmc.Group([
            dmc.Badge(higher['severity'], color=SEVERITY_COLORS.get(higher['severity'], "#fff"), variant="filled"),
            dmc.Text(higher['source'].upper(), size="xs", fw=600)
        ], gap="xs", justify="center")
        
        low_element = dmc.Group([
            dmc.Badge(lower['severity'], color=SEVERITY_COLORS.get(lower['severity'], "#fff"), variant="filled"),
            dmc.Text(lower['source'].upper(), size="xs", fw=600)
        ], gap="xs", justify="center")

        pkg_name = higher['package_name']
        is_fixed = "Available" if higher['is_fixed_available'] or lower['is_fixed_available'] else "-"

        rows.append(html.Tr([
            html.Td(vid, style={"textAlign": "center"}),
            html.Td(pkg_name, style={"textAlign": "center"}),
            html.Td(high_element, style={"textAlign": "center"}),
            html.Td(low_element, style={"textAlign": "center"}),
            html.Td(is_fixed, style={"textAlign": "center"}),
            html.Td(
                dmc.Center(
                    dmc.ActionIcon(DashIconify(icon="mdi:eye"), id={"type": "view-detail", "index": vid}, variant="subtle")
                ),
                style={"textAlign": "center"}
            )
        ]))

    header = html.Thead(
        html.Tr([
            html.Th("ID", style={"textAlign": "center"}),
            html.Th("패키지", style={"textAlign": "center"}),
            html.Th("심각도 (높음)", style={"textAlign": "center"}),
            html.Th("심각도 (낮음)", style={"textAlign": "center"}),
            html.Th("고정 여부", style={"textAlign": "center"}),
            html.Th("상세", style={"textAlign": "center"})
        ]),
        style={"position": "sticky", "top": 0, "backgroundColor": THEME_BG_PAPER, "zIndex": 10}
    )

    return dmc.Table(children=[header, html.Tbody(rows)], withColumnBorders=True, highlightOnHover=True)

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

@callback(Output("system-log-container", "children"), Input("upload-log-store", "data"))
def render_logs(logs):
    if not logs: return dmc.Text("로그가 없습니다.", c="dimmed")
    return [html.Div(f"[{l['time']}] {l['content']}", style={"marginBottom": "4px"}) for l in logs]

# ================================================================
# [클라이언트사이드 콜백] 토큰 획득 & 뷰
# ================================================================
app.clientside_callback(
    """
    function(pathname) {
        const keys = Object.keys(window.localStorage)
            .filter(k => k.startsWith('sb-') && k.endsWith('-auth-token'));
        for (const k of keys) {
            try {
                const v = JSON.parse(window.localStorage.getItem(k));
                if (v && v.access_token) return v.access_token;
            } catch (e) {}
        }
        return null;
    }
    """,
    Output("auth-token-store", "data"),
    Input("url", "pathname")
)

app.clientside_callback(
    """
    function(pathname) {
        const keys = Object.keys(window.localStorage)
            .filter(k => k.startsWith('sb-') && k.endsWith('-auth-token'));
        for (const k of keys) {
            try {
                const v = JSON.parse(window.localStorage.getItem(k));
                if (v && v.user && v.user.email) return '👤 ' + v.user.email;
            } catch (e) {}
        }
        return '';
    }
    """,
    Output("user-email-display", "children"),
    Input("url", "pathname")
)

app.clientside_callback(
    """
    function(n_clicks) {
        if (!n_clicks) return window.dash_clientside.no_update;
        const keys = Object.keys(window.localStorage).filter(k => k.startsWith('sb-'));
        keys.forEach(k => window.localStorage.removeItem(k));
        window.location.href = '/login/';
        return '';
    }
    """,
    Output("_logout-dummy", "children"),
    Input("btn-logout", "n_clicks"),
    prevent_initial_call=True
)

@callback(
    Output("pdf-url-store", "data"),
    Output("upload-log-store", "data", allow_duplicate=True),
    Input("btn-export-pdf", "n_clicks"),
    State("analysis-result-store", "data"),
    State("upload-log-store", "data"),
    State("auth-token-store", "data"),
    prevent_initial_call=True
)
def request_pdf(n_clicks, analysis, current_logs, token):
    def _ts():
        return datetime.datetime.now().strftime("%H:%M:%S")
    if not n_clicks:
        return no_update, no_update
    logs = list(current_logs or [])
    if not analysis or not analysis.get("job_id"):
        logs.insert(0, {"time": _ts(), "content": "PDF 추출 실패 — 먼저 이미지 스캔을 실행해 주세요."})
        return no_update, logs
    job_id = analysis["job_id"]
    logs.insert(0, {"time": _ts(), "content": f"PDF 추출 요청 중 (job {job_id[:8]}...)"})
    
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    try:
        resp = requests.post(
            "http://127.0.0.1:3000/pdf",
            json={"job_id": job_id},
            headers=headers,
            timeout=300,
        )
        data = resp.json()
        if not data.get("ok") or not data.get("url"):
            logs.insert(0, {"time": _ts(), "content": f"PDF 생성 실패: {data.get('error') or resp.status_code}"})
            return no_update, logs
        cached_label = "캐시 재사용" if data.get("cached") else "신규 생성"
        logs.insert(0, {"time": _ts(), "content": f"PDF 다운로드 시작 ({cached_label})"})
        return {"url": data["url"], "ts": _ts()}, logs
    except Exception as e:
        logs.insert(0, {"time": _ts(), "content": f"PDF 통신 장애: {str(e)[:120]}"})
        return no_update, logs

app.clientside_callback(
    """
    function(payload) {
        if (!payload || !payload.url) return window.dash_clientside.no_update;
        try {
            const a = document.createElement('a');
            a.href = payload.url;
            a.setAttribute('download', '');
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); }, 100);
        } catch (e) {
            console.error('PDF 다운로드 트리거 실패:', e);
        }
        return '';
    }
    """,
    Output("_pdf-trigger-dummy", "children"),
    Input("pdf-url-store", "data"),
    prevent_initial_call=True
)

if __name__ == "__main__":
    app.run(debug=False, port=8050)