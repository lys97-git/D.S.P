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
             "requests": "requests"}
for mod, pkg in _REQUIRED.items():
    try: __import__(mod)
    except ImportError: subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# ── 🎨 [디자인 및 색상 정의] ──────────────────────────────────────────────────
THEME_BG_MAIN = "#0a192f"      
THEME_BG_PAPER = "#112240"     
THEME_BORDER = "#233554"       
THEME_TEXT_ACCENT = "#64ffda"  
THEME_TEXT_MAIN = "#ccd6f6"

# 섹션 2: 위험도 색상 통일 (원형 그래프와 테이블 동일 적용)
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff944d",
    "MEDIUM": "#ffd11a",
    "LOW": "#4da6ff",
    "UNKNOWN": "#a6a6a6"
}

# ── 🏗️ [레이아웃] ──────────────────────────────────────────────────────────
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
                    ]),
                ]),

                dmc.Grid(children=[
                    # 왼쪽: 업로드 및 로그
                    dmc.GridCol(span=4, children=[
                        dmc.Paper(withBorder=True, p="md", radius="md", mb="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Text("이미지 분석 설정", fw=700, mb="md", style={"color": THEME_TEXT_ACCENT}),
                            dcc.Loading(id="loading-upload", type="circle", color=THEME_TEXT_ACCENT, children=[
                                dcc.Upload(
                                    id='upload-data',
                                    children=html.Div([
                                        DashIconify(id="upload-icon", icon="tabler:upload", width=30),
                                        dmc.Text("파일을 드래그하세요.", id="upload-text")
                                    ], style={"textAlign": "center"}),
                                    style={'width': '100%', 'height': '100px', 'borderWidth': '2px', 'borderStyle': 'dashed', 'borderColor': THEME_BORDER, 'borderRadius': '8px', 'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center', 'cursor': 'pointer'}
                                )
                            ]),
                            dmc.Space(h=15),
                            dmc.Button("스캔 시작", id="btn-start-scan", fullWidth=True, color="teal")
                        ]),
                        # 섹션 4: 실시간 시스템 로그
                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Text("시스템 진행 로그", fw=700, mb="xs", style={"color": THEME_TEXT_ACCENT}),
                            html.Div(id="system-log-container", style={"height": "200px", "overflowY": "auto", "fontSize": "12px"})
                        ])
                    ]),

                    # 오른쪽: 원형 그래프 (섹션 1)
                    dmc.GridCol(span=8, children=[
                        dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                            dmc.Text("취약점 분포 (심각도)", fw=700, mb="md", style={"color": THEME_TEXT_ACCENT}),
                            dcc.Graph(id="severity-pie-chart", config={'displaylogo': False}) # Plotly 로고 제거
                        ])
                    ])
                ]),

                dmc.Space(h="xl"),

                # 섹션 2 & 3: 결과 테이블
                dmc.Paper(withBorder=True, p="md", radius="md", style={"backgroundColor": THEME_BG_PAPER, "borderColor": THEME_BORDER}, children=[
                    dmc.Group(justify="space-between", mb="md", children=[
                        dmc.Text("취약점 상세 리스트", fw=700, style={"color": THEME_TEXT_ACCENT}),
                        # 도구별 필터 토글
                        dmc.SegmentedControl(
                            id="tool-filter-toggle",
                            data=[{"label": "전체", "value": "ALL"}, {"label": "Trivy", "value": "trivy"}, {"label": "Grype", "value": "grype"}],
                            value="ALL"
                        )
                    ]),
                    # 테이블 상단 고정 및 중앙 정렬 (섹션 2, 3)
                    html.Div(id="vulnerability-table-container", style={"maxHeight": "500px", "overflowY": "auto"})
                ]),

                # 데이터 저장소
                dcc.Store(id="analysis-result-store"),
                dcc.Store(id="upload-log-store"),
                dcc.Store(id="filter-state-store", data={"severity": None}), # 그래프 클릭 필터용

                # 상세 모달
                dmc.Modal(
                    id="detail-modal", title="취약점 상세 분석 결과", size="xl",
                    children=html.Div(id="modal-content"),
                    styles={"content": {"backgroundColor": THEME_BG_PAPER}}
                )
            ]
        )
    ]
)

# ── 🧠 [콜백 함수] ─────────────────────────────────────────────────────────

# [콜백 1: 스캔 실행 및 로그 세분화 (섹션 4)]
@callback(
    Output("analysis-result-store", "data"),
    Output("upload-log-store", "data"),
    Input("btn-start-scan", "n_clicks"),
    State("upload-data", "contents"),
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    running=[
        (Output("loading-overlay", "visible"), True, False),
        (Output("btn-start-scan", "disabled"), True, False),
    ],
    prevent_initial_call=True
)
def run_scan(n_clicks, contents, filename, current_logs):
    if not n_clicks or not contents: return no_update, no_update
    
    logs = current_logs or []
    def add_log(msg): logs.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "content": msg})

    # 단계별 로그 추가
    add_log(f"📁 파일 업로드 완료: {filename}")
    add_log(f"🚀 API 서버로 전송 준비 중...")
    
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        add_log(f"📡 분석 요청 전송 중 (Target: Trivy & Grype)...")
        
        response = requests.post(
            "http://127.0.0.1:8000/scan", 
            files={'file': (filename, io.BytesIO(decoded), 'application/x-tar')},
            data={'user_id': 'admin'},
            timeout=300
        )
        
        if response.status_code == 200:
            add_log(f"✅ 분석 완료 및 데이터 수신 성공")
            return response.json(), logs
        else:
            add_log(f"❌ 서버 에러: {response.status_code}")
            return no_update, logs
    except Exception as e:
        add_log(f"⚠️ 통신 장애: {str(e)}")
        return no_update, logs

# [콜백 2: 원형 그래프 렌더링 (섹션 1)]
@callback(
    Output("severity-pie-chart", "figure"),
    Input("analysis-result-store", "data")
)
def update_pie_chart(data):
    if not data or "vulnerabilities" not in data:
        return px.pie(title="데이터 없음").update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    
    df = pd.DataFrame(data["vulnerabilities"])
    counts = df['severity'].value_counts().reset_index()
    
    fig = px.pie(
        counts, values='count', names='severity',
        color='severity', color_discrete_map=SEVERITY_COLORS,
        hole=0.4
    )
    
    # 마우스 올렸을 때 글자 수정 및 스타일 (섹션 1)
    fig.update_traces(
        hovertemplate="<b>심각도: %{label}</b><br>탐지 건수: %{value}건<br>비중: %{percent}",
        textinfo='label+percent'
    )
    fig.update_layout(
        showlegend=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=THEME_TEXT_MAIN),
        margin=dict(t=0, b=0, l=0, r=0)
    )
    return fig

# [콜백 3: 테이블 렌더링 및 필터링 (섹션 1, 2, 3)]
@callback(
    Output("vulnerability-table-container", "children"),
    Input("analysis-result-store", "data"),
    Input("tool-filter-toggle", "value"),
    Input("severity-pie-chart", "clickData") # 그래프 클릭 감지
)
def update_table(data, tool_filter, click_data):
    if not data: return dmc.Text("분석 결과가 없습니다.", c="dimmed", ta="center", py=50)
    
    df = pd.DataFrame(data["vulnerabilities"])
    
    # 그래프 클릭 필터링 적용 (섹션 1)
    if click_data:
        selected_severity = click_data['points'][0]['label']
        df = df[df['severity'] == selected_severity]
    
    # 도구 필터링 적용 (섹션 2)
    if tool_filter != "ALL":
        df = df[df['source'] == tool_filter]

    # 테이블 헤더 고정 및 중앙 정렬 (섹션 2, 3)
    header = html.Thead(
        html.Tr([
            html.Th("ID", style={"textAlign": "center"}),
            html.Th("패키지", style={"textAlign": "center"}),
            html.Th("심각도", style={"textAlign": "center"}),
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
            html.Td(dmc.ActionIcon(DashIconify(icon="mdi:eye"), id={"type": "view-detail", "index": row['vulnerability_id']}, variant="subtle"))
        ]))
    
    return dmc.Table(children=[header, html.Tbody(rows)], withColumnBorders=True, highlightOnHover=True)

# [콜백 4: 상세 모달 및 설명 한/영 토글 (섹션 2)]
@callback(
    Output("detail-modal", "opened"),
    Output("modal-content", "children"),
    Input({"type": "view-detail", "index": ALL}, "n_clicks"),
    Input("lang-toggle", "value"), # 모달 내 언어 토글
    State("analysis-result-store", "data"),
    prevent_initial_call=True
)
def open_modal(n_clicks, lang, data):
    if not any(n_clicks): return False, no_update
    
    vuln_id = ctx.triggered_id["index"]
    v = next(item for item in data["vulnerabilities"] if item["vulnerability_id"] == vuln_id)
    
    # 설명 언어 처리 (간이 번역 로직 혹은 필드 선택)
    # 실제 API에서 한글을 준다면 v['description_kr'] 등을 쓰면 됨
    description = v.get('description', 'No Description')
    display_desc = f"[번역 예시] {description}" if lang == "KR" else description

    # 모든 항목 표시 (섹션 2 요청 항목 14개)
    fields = [
        ("Source", v['source']), ("Target", v.get('target','-')), ("Class", v.get('result_class','-')),
        ("Type", v.get('result_type','-')), ("Vulnerability ID", v['vulnerability_id']),
        ("Package", v['package_name']), ("Path", v.get('package_path','-')),
        ("Installed", v['installed_version']), ("Fixed", v.get('fixed_version','-')),
        ("Fix Available", str(v['is_fixed_available'])), ("Severity", v['severity']),
        ("Primary URL", html.A(v['primary_url'], href=v['primary_url'], target="_blank") if v['primary_url'] else "-"),
        ("Title", v.get('title', 'No Title'))
    ]

    content = dmc.Stack([
        dmc.Group(justify="space-between", children=[
            dmc.Text(f"상세 정보: {vuln_id}", fw=700, size="lg", style={"color": THEME_TEXT_ACCENT}),
            dmc.SegmentedControl(id="lang-toggle", data=[{"label": "English", "value": "EN"}, {"label": "한국어", "value": "KR"}], value=lang or "EN")
        ]),
        dmc.Grid([
            dmc.GridCol([dmc.Text(label, fw=600, size="sm", c="dimmed"), dmc.Text(str(val), size="md")], span=4)
            for label, val in fields
        ]),
        dmc.Divider(label="Description"),
        dmc.Text(display_desc, size="sm", style={"lineHeight": "1.6"})
    ], gap="md")
    
    return True, content

# [로그 렌더링 콜백]
@callback(Output("system-log-container", "children"), Input("upload-log-store", "data"))
def render_logs(logs):
    if not logs: return dmc.Text("로그가 없습니다.", c="dimmed")
    return [html.Div(f"[{l['time']}] {l['content']}", style={"marginBottom": "4px"}) for l in logs]

if __name__ == "__main__":
    app.run_server(debug=True, port=8050)