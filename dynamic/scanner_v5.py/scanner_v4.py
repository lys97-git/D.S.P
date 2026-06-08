import subprocess   # 외부 보안 도구(Grype, Trivy)를 실행합니다.
import json          # JSON 파싱 및 저장에 사용합니다.
import os            # 파일 경로 생성, 존재 확인, 삭제 등에 사용합니다.
import uuid          # scan_reports.id 등 UUID 생성에 사용합니다.
import asyncio       # 블로킹 subprocess를 스레드풀에서 실행하기 위해 사용합니다.
import sys           # 로그 즉시 출력(flush)에 사용합니다.
import tarfile       # 업로드된 tar 아카이브 유효성 검사에 사용합니다.
import requests      # 분석 결과를 API 서버로 HTTP 전송할 때 사용합니다.
from datetime import datetime, timezone   # UTC 기준 시각 기록에 사용합니다.
from fastapi import FastAPI, UploadFile, File, Form, Request  # 웹 API 구성에 사용합니다. (Request: /analyze 엔드포인트용)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

try:
    from dynamic_backend import attach_dynamic_backend
except Exception as dynamic_backend_error:
    attach_dynamic_backend = None
    print(f"[dynamic] backend disabled: {dynamic_backend_error}")

app = FastAPI()  # FastAPI 애플리케이션 인스턴스를 생성합니다.

# ──────────────────────────────────────────────
# Windows 환경 설정
# - grype/trivy가 PATH에 있으면 바로 실행됩니다.
# - 환경 변수 GRYPE_PATH / TRIVY_PATH 로 명시적 경로 지정 가능합니다.
# ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8050",
        "http://127.0.0.1:8050",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if attach_dynamic_backend:
    attach_dynamic_backend(app)

TOOL_GRYPE = os.environ.get("GRYPE_PATH", "grype")
TOOL_TRIVY = os.environ.get("TRIVY_PATH", "trivy")

# 임시 파일 저장 디렉터리 (Windows에서는 %TEMP% 폴더 사용)
WORK_DIR = os.environ.get("SCANNER_WORK_DIR", os.path.abspath("."))
# 환경 변수가 없으면 현재 디렉토리를 사용합니다.
os.makedirs(WORK_DIR, exist_ok=True)
# WORK_DIR이 없으면 생성합니다.

# API 서버 주소 설정
API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://localhost:3000")
# 환경 변수로 API 서버 주소를 설정하거나 기본값을 사용합니다. (Node.js 서버는 3000 포트)
API_SAVE_ENDPOINT = f"{API_SERVER_URL}/save"
# API 서버의 저장 엔드포인트 주소입니다.
API_TIMEOUT = 30
# API 요청 타임아웃을 30초로 설정합니다.

# 임시 이미지 파일 자동 삭제 여부 (운영: True 권장, 개발 디버깅: False)
CLEANUP_IMAGE_FILE = os.environ.get("CLEANUP_IMAGE_FILE", "true").lower() == "true"
# 환경 변수로 이미지 파일 삭제 여부를 제어합니다.

# ──────────────────────────────────────────────
# DB 스키마 정합성을 위한 상수
# ──────────────────────────────────────────────
# scan_jobs.severity / *_filtered.severity CHECK 제약이 허용하는 5개 표준값입니다.
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def normalize_severity(sev) -> str:
    """
    도구별로 다양한 심각도 값을 DB CHECK 제약이 허용하는 5개 표준값으로 정규화합니다.
    예) None / "" / "Negligible" / "negligible" → "UNKNOWN"
    """
    if not sev:
        # None 또는 빈 문자열이면
        return "UNKNOWN"
        # UNKNOWN 으로 처리합니다.
    s = str(sev).strip().upper()
    # 문자열로 변환 후 공백 제거 및 대문자화합니다.
    if s in ALLOWED_SEVERITIES:
        # 표준값에 해당하면
        return s
        # 그대로 반환합니다.
    return "UNKNOWN"
    # 그 외(Negligible 등 비표준)는 UNKNOWN 으로 매핑합니다.


# ──────────────────────────────────────────────
# 유틸리티: 안전한 파일 경로 생성
# ──────────────────────────────────────────────
def work_path(filename: str) -> str:
    """WORK_DIR 아래의 절대 경로를 반환합니다."""
    return os.path.join(WORK_DIR, filename)
    # os.path.join은 현재 OS의 경로 구분자를 자동으로 처리합니다.


def log(msg: str) -> None:
    """터미널에 즉시 출력합니다 (uvicorn 버퍼링 방지)."""
    print(msg, flush=True)
    # 메시지를 버퍼링 없이 바로 출력합니다.
    sys.stdout.flush()
    # stdout 스트림을 강제로 플러시합니다.


async def save_upload_chunked(upload: UploadFile, dest: str, chunk_size: int = 1024 * 1024) -> None:
    """
    대용량 파일을 1 MB 청크 단위로 읽어 저장합니다.
    await file.read() 로 전체를 메모리에 올리면 수백 MB tar 파일에서
    이벤트 루프가 장시간 블로킹되므로, 청크 방식으로 교체합니다.
    """
    with open(dest, "wb") as out:
        # 파일을 이진 쓰기 모드로 엽니다.
        while True:
            # 청크 단위로 반복해서 읽습니다.
            chunk = await upload.read(chunk_size)
            # chunk_size 바이트씩 파일을 읽습니다.
            if not chunk:
                # 더 이상 데이터가 없으면 루프를 종료합니다.
                break
            out.write(chunk)
            # 읽은 데이터를 파일에 씁니다.


async def run_tool(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """
    블로킹 subprocess.run 을 asyncio 스레드풀에서 실행합니다.
    FastAPI async 핸들러 안에서 subprocess.run 을 직접 호출하면
    uvicorn 이벤트 루프 전체가 블로킹되어 응답이 오지 않습니다.
    loop.run_in_executor 로 별도 스레드에서 실행해 이를 방지합니다.
    timeout: 초 단위 (기본 600초 = 10분, Trivy DB 다운로드 포함 여유 시간)
    """
    loop = asyncio.get_event_loop()
    # 현재 이벤트 루프를 가져옵니다.
    return await loop.run_in_executor(
        # 스레드풀에서 실행할 작업을 등록합니다.
        None,
        lambda: subprocess.run(
            # None은 기본 스레드풀을 사용한다는 의미입니다.
            cmd,
            # 실행할 명령어 리스트입니다.
            capture_output=True,
            # 표준 출력과 표준 에러를 캡처합니다.
            text=True,
            # 출력을 문자열로 반환합니다.
            encoding="utf-8",
            # UTF-8 인코딩을 사용합니다.
            errors="replace",
            # Windows 등에서 디코딩 실패 시 깨진 문자를 치환하여 예외를 막습니다.
            timeout=timeout
            # 지정된 시간(초) 내에 완료되어야 합니다.
        )
    )


async def ensure_trivy_db() -> bool:
    """
    Trivy 취약점 DB가 없거나 오래된 경우 미리 다운로드합니다.
    스캔 요청 때마다 DB를 받으면 타임아웃이 나므로,
    스캔 전에 DB 상태를 확인하고 필요할 때만 업데이트합니다.
    반환값: True(정상) / False(DB 업데이트 실패)
    """
    log("[*] Trivy DB 상태 확인 중...")
    # DB 확인 시작 로그를 출력합니다.
    res = await run_tool(
        # Trivy DB 다운로드 명령을 실행합니다.
        [TOOL_TRIVY, "image", "--download-db-only"],
        # Trivy 이미지 스캔 DB만 다운로드합니다.
        timeout=1800  # DB 다운로드는 최대 30분 허용
        # 긴 타임아웃을 설정하여 DB 다운로드 시간을 충분히 줍니다.
    )
    if res.returncode == 0:
        # 명령이 성공했으면 (반환 코드 0)
        log("[+] Trivy DB 준비 완료")
        # 성공 로그를 출력합니다.
        return True
        # True를 반환합니다.
    else:
        # 명령이 실패했으면
        log(f"[!] Trivy DB 업데이트 실패: {res.stderr[:300]}")
        # 에러 메시지의 처음 300자를 출력합니다.
        return False
        # False를 반환합니다.


async def send_to_api_server(payload: dict, endpoint: str = None) -> bool:
    """
    스캔 결과를 API 서버로 전송합니다.
    payload: 전송할 데이터입니다.
    endpoint: API 엔드포인트 URL입니다 (기본값: API_SAVE_ENDPOINT).
    반환값: True(성공) / False(실패)
    """
    if endpoint is None:
        # 엔드포인트가 지정되지 않으면
        endpoint = API_SAVE_ENDPOINT
        # 기본 엔드포인트를 사용합니다.
    
    try:
        # API 요청을 시도합니다.
        log(f"[*] API 서버로 결과 전송 중: {endpoint}")
        # API 전송 시작 로그를 출력합니다.
        # 동기 라이브러리 requests 를 그대로 await 하면 이벤트 루프가 블로킹되므로
        # run_in_executor 로 별도 스레드에서 실행합니다.
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(endpoint, json=payload, timeout=API_TIMEOUT)
        )
        # POST 요청으로 JSON 데이터를 전송합니다.
        
        if response.status_code in [200, 201]:
            # 성공 상태 코드면 (200 OK, 201 Created)
            log(f"[+] API 서버 전송 성공 (상태: {response.status_code})")
            # 성공 로그를 출력합니다.
            try:
                # 응답 바디를 파싱합니다.
                resp_data = response.json()
                log(f"[+] 응답: {resp_data}")
                # 응답 데이터를 로그에 출력합니다.
            except:
                # 응답 파싱 실패 시
                log(f"[+] 응답 바디: {response.text[:500]}")
                # 응답 텍스트의 처음 500자를 출력합니다.
                resp_data = None
            return {
                "ok": True,
                "job_id": (resp_data or {}).get("job_id") if isinstance(resp_data, dict) else None,
                "response": resp_data if isinstance(resp_data, dict) else None,
                "error": None,
            }
        else:
            # 실패 상태 코드면
            log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
            # 실패 로그와 응답 텍스트를 출력합니다.
            return {
                "ok": False,
                "job_id": None,
                "response": None,
                "error": response.text[:300],
            }
            
    except requests.exceptions.Timeout:
        # 타임아웃 예외 발생 시
        log(f"[!] API 서버 요청 타임아웃 ({API_TIMEOUT}초)")
        # 타임아웃 로그를 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": "timeout"}
    except requests.exceptions.ConnectionError:
        # 연결 실패 예외 발생 시
        log(f"[!] API 서버 연결 실패: {endpoint}")
        # 연결 실패 로그를 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": "connection_error"}
    except Exception as e:
        # 기타 예외 발생 시
        log(f"[!] API 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        # 예외 정보를 로그에 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": str(e)[:300]}


async def send_all_files_to_api(
    payload: dict,
    json_files: dict,
    endpoint: str = None,
    auth_token: str = ""
) -> dict:
    """
    모든 JSON 파일을 포함하여 API 서버로 전송합니다.
    payload: 최종 payload 데이터입니다.
    json_files: {파일_이름: 파일_경로} 형식의 JSON 파일 딕셔너리입니다.
    endpoint: API 엔드포인트 URL입니다 (기본값: API_SAVE_ENDPOINT).
    반환값: {"ok": bool, "job_id": str|None, "response": dict|None, "error": str|None}
    """
    if endpoint is None:
        # 엔드포인트가 지정되지 않으면
        endpoint = API_SAVE_ENDPOINT
        # 기본 엔드포인트를 사용합니다.
    
    try:
        # API 요청을 시도합니다.
        log(f"[*] API 서버로 모든 파일 전송 중: {endpoint}")
        # 파일 전송 시작 로그를 출력합니다.
        
        # multipart/form-data 형식으로 파일 준비
        files = {}
        # 파일 딕셔너리를 초기화합니다.
        
        # JSON 파일들을 파일 딕셔너리에 추가
        for file_name, file_path in json_files.items():
            # 각 JSON 파일에 대해 반복합니다.
            if os.path.exists(file_path):
                # 파일이 존재하면
                with open(file_path, 'rb') as f:
                    # 파일을 이진 모드로 엽니다.
                    file_content = f.read()
                    # 파일 내용을 읽습니다.
                    files[file_name] = (file_name, file_content, 'application/json')
                    # multipart 형식으로 파일을 추가합니다.
                log(f"  [준비] {file_name}: {len(file_content) / 1024:.1f} KB")
                # 파일 크기를 로그합니다.
            else:
                # 파일이 없으면
                log(f"  [경고] 파일 없음: {file_path}")
                # 경고 로그를 출력합니다.
        
        # 데이터 필드에 최종 payload를 JSON 문자열로 추가
        data = {
            # 폼 데이터를 준비합니다.
            'payload': json.dumps(payload)
            # 최종 payload를 JSON 문자열로 변환합니다.
        }
        
        # multipart/form-data로 전송 (동기 requests를 executor로 감싸 블로킹 방지)
        auth_headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(
                endpoint,
                files=files,
                data=data,
                headers=auth_headers,
                timeout=180  # 파일 전송 + Node 백그라운드 응답 안전망 (3분)
            )
        )
        # POST 요청을 보냅니다.
        
        if response.status_code in [200, 201]:
            # 성공 상태 코드면 (200 OK, 201 Created)
            log(f"[+] API 서버 전송 성공 (상태: {response.status_code})")
            # 성공 로그를 출력합니다.
            try:
                # 응답 바디를 파싱합니다.
                resp_data = response.json()
                log(f"[+] 응답: {resp_data}")
                # 응답 데이터를 로그에 출력합니다.
            except:
                # 응답 파싱 실패 시
                log(f"[+] 응답 바디: {response.text[:500]}")
                # 응답 텍스트의 처음 500자를 출력합니다.
                resp_data = None
            return {
                "ok": True,
                "job_id": (resp_data or {}).get("job_id") if isinstance(resp_data, dict) else None,
                "response": resp_data if isinstance(resp_data, dict) else None,
                "error": None,
            }
        else:
            # 실패 상태 코드면
            log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
            # 실패 로그와 응답 텍스트를 출력합니다.
            return {
                "ok": False,
                "job_id": None,
                "response": None,
                "error": response.text[:300],
            }
            
    except requests.exceptions.Timeout:
        # 타임아웃 예외 발생 시
        log(f"[!] API 서버 요청 타임아웃 (180초)")
        # 타임아웃 로그를 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": "timeout"}
    except requests.exceptions.ConnectionError:
        # 연결 실패 예외 발생 시
        log(f"[!] API 서버 연결 실패: {endpoint}")
        # 연결 실패 로그를 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": "connection_error"}
    except Exception as e:
        # 기타 예외 발생 시
        log(f"[!] 파일 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        # 예외 정보를 로그에 출력합니다.
        return {"ok": False, "job_id": None, "response": None, "error": str(e)[:300]}


# ──────────────────────────────────────────────
# 헬스체크 엔드포인트 (Node.js 서버가 Python 스캐너 생존 확인용)
# ──────────────────────────────────────────────
@app.get("/health")
async def health():
    """Node.js 서버가 Python 스캐너의 동작 여부를 확인하는 엔드포인트입니다."""
    return {"status": "ok", "service": "DSP Python Scanner"}
    # 살아있음을 알리는 간단한 응답을 반환합니다.


# ──────────────────────────────────────────────
# 교차 분석 전용 엔드포인트 (Node.js 워커에서 호출)
# 이미 실행된 Trivy/Grype 원시 JSON을 받아
# filter_results + build_scan_report 만 수행합니다.
# 스캔 재실행이 없으므로 빠르고 중복이 없습니다.
# ──────────────────────────────────────────────
@app.post("/analyze")
async def analyze_endpoint(request: Request):
    """
    요청 body (JSON):
      {
        "job_id":     "<jobId>",
        "image_name": "<filename>",
        "trivy":      { ...Trivy 원시 JSON... },
        "grype":      { ...Grype 원시 JSON... }
      }
    Node.js 워커에서 Trivy/Grype를 직접 실행한 뒤
    교차 분석만 Python 에 위임할 때 호출합니다.
    """
    body       = await request.json()
    # 요청 본문을 JSON으로 파싱합니다.
    grype_raw  = body.get("grype", {})
    # Grype 원시 결과를 추출합니다.
    trivy_raw  = body.get("trivy", {})
    # Trivy 원시 결과를 추출합니다.
    job_id     = body.get("job_id", "unknown")
    # 작업 ID를 추출합니다.
    image_name = body.get("image_name", "")
    # 이미지 이름을 추출합니다.

    filtered_data   = filter_results(grype_raw, trivy_data=trivy_raw)
    # Grype와 Trivy 결과를 정제합니다.
    severity_counts = count_by_severity(filtered_data)
    # 심각도별 집계를 계산합니다.
    scan_report     = build_scan_report(
        # scan_reports 데이터를 구성합니다.
        filtered_data=filtered_data,
        scan_job_id=job_id,
        user_id=job_id,
        image_tag=image_name,
    )

    log(
        f"[Analyze] job={job_id} | "
        f"grype_only={scan_report['grype_only']} | "
        f"trivy_only={scan_report['trivy_only']} | "
        f"mismatch={scan_report['mismatch_count']}"
    )
    # 분석 완료 로그를 출력합니다.

    return {
        "scan_report":     scan_report,
        "filtered_data":   filtered_data,
        "severity_counts": severity_counts,
    }
    # 분석 결과를 반환합니다.


# ──────────────────────────────────────────────
# 메인 스캔 엔드포인트
# ──────────────────────────────────────────────
@app.post("/scan")
async def custom_scan_endpoint(
    user_id: str = Form(...),
    # ── [v4 호환 수정] scan_name 을 옵셔널로 완화 ───────────────────────────────
    # v4 프론트엔드는 scan_name 을 전송하지 않습니다.
    # Form(...) 필수로 두면 422 Unprocessable Entity 가 발생하므로
    # 기본값 "dashboard_scan" 을 부여하여 v4 가 누락해도 통과되게 합니다.
    # v3 같은 구버전 클라이언트가 값을 보내면 자기 값으로 덮어쓰므로 호환에는 영향 없음.
    scan_name: str = Form("dashboard_scan"),
    # ── [v4 호환 수정] scan_tool 도 기본값 유지 ─────────────────────────────────
    # v4 는 scan_tool 도 전송하지 않지만 기본값 "trivy+grype" 가 있어 문제 없음.
    scan_tool: str = Form("trivy+grype"),
    auth_token: str = Form(""),
    file: UploadFile = File(...)
):
    """
    [전체 흐름 요약]
    1. 업로드된 이미지를 임시 파일로 저장
    2. Grype → 패키지 취약점 스캔
    3. Trivy → 취약점 + 시크릿 정밀 분석
    4. 결과 정제 및 심각도별 카운트 집계
    5. scan_reports 레코드 생성 (Grype·Trivy 교차 분석)
    6. 최종 payload 구성 후 카테고리별 JSON 파일로 저장
    7. 임시 파일 전체 삭제 (finally 블록)
    """

    # ── 임시 파일 경로 정의 (WORK_DIR 기준, Windows 친화적) ──────────────────────
    safe_uid = user_id.replace("/", "_").replace("\\", "_")
    # Windows와 Linux 경로 구분자를 모두 언더스코어로 치환하여 경로 인젝션을 방지합니다.
    image_path    = work_path(f"temp_{safe_uid}_{file.filename}")
    # 업로드 이미지 파일의 임시 저장 경로입니다.
    trivy_raw_file= work_path(f"trivy_{safe_uid}.json")
    # Trivy 실행 결과의 JSON 파일 경로입니다.
    grype_raw_file= work_path(f"grype_{safe_uid}.json")
    # Grype 실행 결과의 JSON 파일 경로입니다.

    # 이미지 파일은 용량이 크므로 cleanup 대상에 포함합니다 (CLEANUP_IMAGE_FILE 환경변수로 제어).
    files_to_cleanup = [image_path]
    # 이미지 파일을 정리 대상으로 지정합니다.

    # DB CHECK 제약(scan_jobs.trivy_status / grype_status)이 허용하는 값으로 초기화합니다.
    trivy_status = "pending"
    # Trivy 스캔 상태를 초기화합니다. (DB CHECK: pending/running/completed/failed/skipped)
    grype_status = "pending"
    # Grype 스캔 상태를 초기화합니다. (DB CHECK: pending/running/completed/failed/skipped)
    started_at   = datetime.now(timezone.utc).isoformat()
    # 스캔 시작 시각을 ISO 형식으로 기록합니다.

    # ── scan_tool 파라미터 처리: "trivy", "grype", "trivy+grype" ───────────────
    scan_tool_lc = (scan_tool or "trivy+grype").lower()
    run_grype = "grype" in scan_tool_lc
    run_trivy = "trivy" in scan_tool_lc
    if not run_grype and not run_trivy:
        run_grype = True
        run_trivy = True
    log(f"[*] 스캔 도구 선택: {scan_tool_lc} (grype={run_grype}, trivy={run_trivy})")

    try:
        # ── 단계 1: 이미지 파일 임시 저장 (청크 방식) ───────────────────────────
        log(f"[*] 단계 0: 파일 저장 중 → {image_path}")
        # 파일 저장 시작 로그를 출력합니다.
        await save_upload_chunked(file, image_path)
        # 업로드된 파일을 청크 단위로 저장합니다.
        size_mb = os.path.getsize(image_path) / (1024 * 1024)
        # 저장된 파일의 크기를 MB로 계산합니다.
        log(f"[+] 파일 저장 완료: {size_mb:.1f} MB")
        # 파일 저장 완료 로그를 출력합니다.
        if size_mb < 0.01:
            msg = f"유효한 tar 아카이브가 아닙니다: {file.filename} ({size_mb:.3f} MB)"
            log(f"[!] {msg}")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "Error",
                    "detail": msg,
                    "scan_job": {
                        "status": "failed",
                        "trivy_status": "skipped",
                        "grype_status": "skipped",
                        "file_name": file.filename,
                    },
                },
            )

        try:
            with tarfile.open(image_path, "r:*"):
                pass
        except tarfile.TarError as tar_err:
            msg = f"유효한 tar 아카이브가 아닙니다: {file.filename} ({str(tar_err)[:120]})"
            log(f"[!] {msg}")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "Error",
                    "detail": msg,
                    "scan_job": {
                        "status": "failed",
                        "trivy_status": "skipped",
                        "grype_status": "skipped",
                        "file_name": file.filename,
                    },
                },
            )

        # ── 단계 1: Grype 실행 ── 패키지 취약점 스캔 ────────────────────────────
        if run_grype:
            log("[*] 단계 1: Grype 실행 중...")
            grype_res = await run_tool([TOOL_GRYPE, image_path, "-o", "json"])
            if grype_res.returncode == 0 and grype_res.stdout:
                grype_raw    = json.loads(grype_res.stdout)
                grype_status = "completed"
                with open(grype_raw_file, "w", encoding="utf-8") as f:
                    json.dump(grype_raw, f)
                log(f"[+] Grype 완료: {len(grype_raw.get('matches', []))} 매칭")
            else:
                grype_raw    = {}
                grype_status = "failed"
                log(f"[!] Grype 실패 (returncode={grype_res.returncode}): {grype_res.stderr[:300]}")
        else:
            grype_raw    = {}
            grype_status = "skipped"
            log("[*] 단계 1: Grype 건너뜀 (scan_tool 미선택)")

        # ── 단계 2: Trivy 실행 ── 취약점 + 시크릿 정밀 분석 ────────────────────
        if run_trivy:
            await ensure_trivy_db()
            log("[*] 단계 2: Trivy 실행 중...")
            trivy_res = await run_tool([
                TOOL_TRIVY, "image",
                "--input", image_path,
                "--format", "json",
                "--scanners", "vuln,secret"
            ])
            if trivy_res.returncode == 0 and trivy_res.stdout:
                trivy_raw    = json.loads(trivy_res.stdout)
                trivy_status = "completed"
                with open(trivy_raw_file, "w", encoding="utf-8") as f:
                    json.dump(trivy_raw, f)
                log(f"[+] Trivy 완료: {len(trivy_raw.get('Results', []))} 결과 블록")
            else:
                trivy_raw    = {}
                trivy_status = "failed"
                log(f"[!] Trivy 실패 (returncode={trivy_res.returncode}): {trivy_res.stderr[:300]}")
        else:
            trivy_raw    = {}
            trivy_status = "skipped"
            log("[*] 단계 2: Trivy 건너뜀 (scan_tool 미선택)")

        # ── 단계 3: 데이터 정제 및 심각도 집계 ──────────────────────────────────
        filtered_data   = filter_results(grype_raw, trivy_data=trivy_raw)
        # Grype와 Trivy 결과를 정제합니다.
        severity_counts = count_by_severity(filtered_data)
        # 취약점을 심각도별로 집계합니다. (filtered_data dict 전달)
        finished_at     = datetime.now(timezone.utc).isoformat()
        # 스캔 완료 시각을 ISO 형식으로 기록합니다.

        # ── 단계 4: scan_reports 레코드 생성 (Grype·Trivy 교차 분석) ────────────
        scan_report = build_scan_report(
            # scan_reports 테이블을 위한 데이터를 구성합니다.
            filtered_data=filtered_data,
            scan_job_id=None,   
            # scan_job_id는 백엔드에서 나중에 채웁니다.
            user_id=user_id,
            # 사용자 ID를 전달합니다.
            image_tag=file.filename,
            # 이미지 파일명을 전달합니다.
            report_path=None    
            # report_path는 나중에 채울 수 있습니다.
        )

        # ── 단계 5: 최종 payload 구성 ────────────────────────────────────────────
        # ── 심각도 전체 합산 (scan_jobs 테이블용) ────────────────────────────────
        # 전체 고유 취약점 = grype + trivy 합집합 (mismatch / common 모두 포함)
        all_vuln_ids = set()
        for v in filtered_data.get("grype_vulnerabilities", []):
            vid = v.get("vulnerability_id")
            if vid:
                all_vuln_ids.add(vid)
        for v in filtered_data.get("trivy_vulnerabilities", []):
            vid = v.get("vulnerability_id")
            if vid:
                all_vuln_ids.add(vid)
        # 전체 고유 취약점 ID 집합을 만듭니다.

        def _total_sev(sev_key):
            return sum(
                severity_counts[cat].get(sev_key, 0)
                for cat in severity_counts
            )

        # 전체 스캔 status 결정 (DB CHECK: pending/uploaded/running/completed/failed/cancelled)
        # 하나라도 failed 면 failed, 둘 다 completed 면 completed
        if grype_status == "failed" and trivy_status == "failed":
            overall_status = "failed"
        elif grype_status == "completed" or trivy_status == "completed":
            overall_status = "completed"
        else:
            overall_status = "failed"

        final_payload = {
            # 최종 응답 payload를 구성합니다.
            "scan_job": {
                # scan_jobs 테이블을 위한 정보입니다.
                "user_id":               user_id,
                # 사용자 ID입니다.
                "scan_name":             scan_name,
                # 스캔 이름입니다.
                "file_name":             file.filename,
                # 원본 업로드 파일명입니다. (scan_jobs.file_name)
                "file_type":             "image_tar",
                # 파일 유형입니다. (scan_jobs.file_type, NOT NULL, CHECK: image_tar/dockerfile/sbom)
                "image_name":            file.filename,
                # 이미지 이름입니다. (scan_jobs.image_name)
                "status":                overall_status,
                # 전체 스캔 상태입니다. (DB CHECK: completed/failed 등)
                "grype_status":          grype_status,
                # Grype 스캔 상태입니다. (DB CHECK: completed/failed 등)
                "trivy_status":          trivy_status,
                # Trivy 스캔 상태입니다. (DB CHECK: completed/failed 등)
                "started_at":            started_at,
                # 스캔 시작 시각입니다.
                "finished_at":           finished_at,
                # 스캔 완료 시각입니다.
                "total_vulnerabilities": len(all_vuln_ids),
                # 전체 고유 취약점 수입니다. (Grype ∪ Trivy)
                "critical_count":        _total_sev("CRITICAL"),
                # CRITICAL 심각도 취약점 수입니다.
                "high_count":            _total_sev("HIGH"),
                # HIGH 심각도 취약점 수입니다.
                "medium_count":          _total_sev("MEDIUM"),
                # MEDIUM 심각도 취약점 수입니다.
                "low_count":             _total_sev("LOW"),
                # LOW 심각도 취약점 수입니다.
                "unknown_count":         _total_sev("UNKNOWN"),
                # UNKNOWN 심각도 취약점 수입니다.
                "severity_counts":       severity_counts,
                # 분류별 심각도 상세 (백엔드 참고용, DB 컬럼 아님).
            },
            # scan_reports 데이터입니다.
            "scan_report":  scan_report,
            # 스캔 결과 요약입니다.
            "filtered_data": filtered_data,
        }

        # ── [v4 호환 어댑터] front_end_v4.py 전용 ───────────────────────────────
        # v4 대시보드는 scan_result["summary"], scan_result["vulnerabilities"] 를
        # 다음 규격으로 직접 사용합니다:
        #   - summary: UPPERCASE 키 ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        #   - vulnerabilities: 각 항목이 아래 14개 필드를 가짐
        #       vulnerability_id, package_name, severity(UPPERCASE), source,
        #       is_fixed_available, installed_version, fixed_version, target,
        #       result_class, result_type, package_path, primary_url, title, description
        # v3 어댑터(Capitalized severity / pkg_name·pkg_path) 는 폐기되었습니다.
        # filtered_data 의 grype_vulnerabilities / trivy_vulnerabilities raw 객체에
        # 이미 거의 동일한 키가 들어 있으므로 변환은 최소화합니다.
        dash_vulns = []
        # v4 가 사용할 통합 취약점 리스트입니다.
        seen_ids = set()
        # 중복 vulnerability_id 제거용 집합입니다.

        # Grype 결과를 v4 스키마로 변환
        for v in filtered_data.get("grype_vulnerabilities", []):
            vid = v.get("vulnerability_id")
            if not vid or vid in seen_ids:
                # ID 가 없거나 이미 처리된 항목은 건너뜁니다.
                continue
            seen_ids.add(vid)
            dash_vulns.append({
                "vulnerability_id":   vid,
                # 취약점 ID (CVE-... 형식)
                "package_name":       v.get("package_name") or "",
                # 패키지 이름 (v4 키: package_name)
                "package_path":       v.get("install_path") or "",
                # 패키지 경로 (Grype 는 install_path 를 사용 → v4 의 package_path 로 매핑)
                "installed_version":  v.get("version") or "",
                # 설치된 버전 (Grype 는 version → v4 의 installed_version 으로 매핑)
                "fixed_version":      v.get("fix_version") or "",
                # 수정 버전 (Grype 는 fix_version → v4 의 fixed_version 으로 매핑)
                "severity":           (v.get("severity") or "UNKNOWN").upper(),
                # 심각도 (이미 normalize_severity 로 UPPERCASE 이지만 안전망으로 한번 더)
                "source":             "grype",
                # 도구 출처 (v4 의 도구 필터 토글에서 사용)
                "is_fixed_available": bool(v.get("is_fixed_available")),
                # 수정 가능 여부 (v4 의 모달에서 사용)
                "target":             "",
                # Grype 결과에는 target 개념이 없음 → 빈 문자열
                "result_class":       "",
                # Grype 결과에는 result_class 개념이 없음 → 빈 문자열
                "result_type":        v.get("package_type") or "",
                # Grype 의 package_type 을 v4 의 result_type 으로 매핑 (os/lang 등)
                "primary_url":        "",
                # Grype 는 PrimaryURL 미제공 → 빈 문자열
                "title":              "",
                # Grype 는 Title 미제공 → 빈 문자열
                "description":        v.get("description") or "",
                # 취약점 설명
            })

        # Trivy 결과를 v4 스키마로 변환
        for v in filtered_data.get("trivy_vulnerabilities", []):
            vid = v.get("vulnerability_id")
            if not vid or vid in seen_ids:
                # ID 가 없거나 Grype 에서 이미 처리된 항목은 건너뜁니다.
                # (중복 시 Grype 데이터가 우선됨 — Grype 가 OS 패키지에 더 정확)
                continue
            seen_ids.add(vid)
            dash_vulns.append({
                "vulnerability_id":   vid,
                "package_name":       v.get("package_name") or "",
                "package_path":       v.get("package_path") or "",
                # Trivy 는 이미 package_path 키를 사용 (그대로 매핑)
                "installed_version":  v.get("installed_version") or "",
                "fixed_version":      v.get("fixed_version") or "",
                "severity":           (v.get("severity") or "UNKNOWN").upper(),
                "source":             "trivy",
                "is_fixed_available": bool(v.get("is_fixed_available")),
                "target":             v.get("target") or "",
                # Trivy 의 target (예: "Java", "alpine 3.18.0 (alpine 3.18.0)")
                "result_class":       v.get("result_class") or "",
                # Trivy 의 result_class (예: "lang-pkgs", "os-pkgs")
                "result_type":        v.get("result_type") or "",
                # Trivy 의 result_type (예: "jar", "apk")
                "primary_url":        v.get("primary_url") or "",
                # Trivy 가 제공하는 공식 어드바이저리 URL
                "title":              v.get("title") or "",
                # Trivy 가 제공하는 취약점 한 줄 제목
                "description":        v.get("description") or "",
            })

        # v4 의 도넛 차트와 요약 카드용 집계 (UPPERCASE 키)
        dash_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for dv in dash_vulns:
            s = dv["severity"]
            if s in dash_summary:
                dash_summary[s] += 1
            else:
                # 만에 하나 비표준 값이 흘러 들어오면 UNKNOWN 으로 합산
                dash_summary["UNKNOWN"] += 1

        # final_payload 최상위에 v4 가 직접 읽는 두 키를 노출
        final_payload["summary"]         = dash_summary
        final_payload["vulnerabilities"] = dash_vulns
        # ── [v4 호환 어댑터 끝] ─────────────────────────────────────────────────

        # ── 단계 6: API 서버로 모든 결과 전송 ───────────────────────────────────────
        log("[*] 단계 6: 모든 JSON 파일을 API 서버로 전송...")
        # API 전송 시작을 로그합니다.

        # 전송할 JSON 파일들을 정리 (Grype + Trivy RAW + 분석 결과)
        json_files_to_send = {
            "grype.json": grype_raw_file,
            # Grype 원본 결과 파일입니다.
            "trivy.json": trivy_raw_file,
            # Trivy 원본 결과 파일입니다.
            "result_scan_report.json": work_path(f"result_scan_report_{safe_uid}.json"),
            # 스캔 보고서 요약 파일입니다.
            # ── 메인: OS / App 취약점 전체 ──────────────────────────────────────
            "result_grype_vulnerabilities.json": work_path(f"result_grype_vulnerabilities_{safe_uid}.json"),
            # Grype가 발견한 OS 취약점 전체입니다.
            "result_trivy_vulnerabilities.json": work_path(f"result_trivy_vulnerabilities_{safe_uid}.json"),
            # Trivy가 발견한 App 취약점 전체입니다.
            "result_secrets.json": work_path(f"result_secrets_{safe_uid}.json"),
            # Trivy가 발견한 시크릿 전체입니다.
            # ── 부가: 교차 분석 결과 ─────────────────────────────────────────────
            "result_cross_analysis.json": work_path(f"result_cross_analysis_{safe_uid}.json"),
            # grype_only / trivy_only / mismatch 교차 분석 결과입니다.
        }
        
        # 먼저 JSON 파일들을 디스크에 저장
        log("[*] JSON 파일들을 디스크에 저장 중...")
        # 파일 저장 시작을 로그합니다.
        _dump(grype_raw_file, grype_raw)
        # Grype 원본 결과를 저장합니다.
        _dump(trivy_raw_file, trivy_raw)
        # Trivy 원본 결과를 저장합니다.
        _dump(work_path(f"result_scan_report_{safe_uid}.json"), scan_report)
        # 스캔 보고서를 저장합니다.
        # ── 메인 데이터 저장 ────────────────────────────────────────────────────
        _dump(work_path(f"result_grype_vulnerabilities_{safe_uid}.json"), filtered_data["grype_vulnerabilities"])
        # Grype OS 취약점 전체를 저장합니다.
        _dump(work_path(f"result_trivy_vulnerabilities_{safe_uid}.json"), filtered_data["trivy_vulnerabilities"])
        # Trivy App 취약점 전체를 저장합니다.
        _dump(work_path(f"result_secrets_{safe_uid}.json"), filtered_data["secrets"])
        # 시크릿 전체를 저장합니다.
        # ── 부가 교차 분석 저장 ─────────────────────────────────────────────────
        _dump(work_path(f"result_cross_analysis_{safe_uid}.json"), {
            "grype_only": filtered_data["grype_only"],
            "trivy_only": filtered_data["trivy_only"],
            "mismatch":   filtered_data["mismatch"],
        })
        # 교차 분석 결과를 저장합니다.
        log("[+] JSON 파일 저장 완료")
        # 파일 저장 완료 로그를 출력합니다.
        
        # 모든 파일을 API 서버로 전송
        api_result = await send_all_files_to_api(
            final_payload,
            json_files_to_send,
            auth_token=auth_token
        )
        # 최종 payload와 모든 JSON 파일을 API 서버로 전송합니다.
        if api_result.get("ok"):
            # API 전송이 성공하면
            log("[+] API 서버 전송 완료")
            # 전송 완료 로그를 출력합니다.
            if api_result.get("job_id"):
                final_payload["job_id"] = api_result["job_id"]
                log(f"[+] job_id 수신: {api_result['job_id']}")
        else:
            # API 전송이 실패하면
            log("[!] API 서버 전송 실패 - 로컬에 백업 보존")
            # 로컬 백업 보존 로그를 출력합니다.

        log(
            f"[+] 스캔 완료. "
            f"전체 고유 취약점: {len(all_vuln_ids)} / "
            f"교차분석(grype_only+trivy_only+mismatch): {len(filtered_data['vulnerabilities'])} / "
            f"시크릿: {len(filtered_data['secrets'])}"
        )
        # 스캔 완료 로그를 출력합니다. (전체/교차분석 수치를 명확히 구분)

        return final_payload

    except Exception as e:
        # 예외 발생 시
        log(f"[!] 예외 발생: {type(e).__name__}: {str(e)[:500]}")
        # 예외 유형과 메시지를 로그에 출력합니다.

        # ── API 서버로 에러 정보 전송 ────────────────────────────────────────────
        error_payload = {
            # 에러 정보를 구성합니다.
            "scan_job": {
                # 스캔 작업 정보입니다.
                "user_id":       user_id,
                # 사용자 ID입니다.
                "scan_name":     scan_name,
                # 스캔 이름입니다. (v4 가 미전송 시 기본값 "dashboard_scan" 이 들어옴)
                "file_name":     file.filename,
                # 파일명입니다.
                "file_type":     "image_tar",
                # 파일 유형입니다. (scan_jobs.file_type, NOT NULL)
                "status":        "failed",
                # 스캔 상태를 실패로 표시합니다. (DB CHECK 제약: failed 허용)
                "error_message": str(e)[:500],
                # 에러 메시지입니다 (처음 500자).
                "started_at":    started_at,
                # 스캔 시작 시각입니다.
                "finished_at":   datetime.now(timezone.utc).isoformat()
                # 스캔 종료 시각입니다.
            }
        }
        
        try:
            # API로 에러를 전송합니다.
            log("[*] 에러 정보를 API 서버로 전송 중...")
            # 에러 전송 시작 로그를 출력합니다.
            await send_to_api_server(error_payload)
            # 에러 payload를 API 서버로 전송합니다.
            log("[+] 에러 정보 전송 완료")
            # 에러 전송 완료 로그를 출력합니다.
        except Exception as api_error:
            # API 전송 중 예외 발생 시
            log(f"[!] 에러 정보 전송 실패: {str(api_error)[:300]}")
            # 에러 전송 실패 로그를 출력합니다.
            try:
                # 로컬 백업으로 에러 정보를 저장합니다.
                _dump(work_path(f"error_info_{user_id.replace('/', '_')}.json"), error_payload)
                # 에러 정보를 JSON 파일로 저장합니다.
            except:
                # 로컬 저장도 실패 시
                pass
                # 조용히 넘어갑니다.

        return {"status": "Error", "detail": str(e)}
        # 에러 응답을 반환합니다.

    finally:
        # ── 정리 작업 ──────────────────────────────────────────────────────────
        # 임시 이미지 파일 삭제 (CLEANUP_IMAGE_FILE=false 환경변수로 보존 가능)
        if CLEANUP_IMAGE_FILE:
            # 자동 삭제 모드면
            for f_path in files_to_cleanup:
                # 정리 대상 파일들을 반복합니다.
                try:
                    if os.path.exists(f_path):
                        # 파일이 존재하면
                        size_kb = os.path.getsize(f_path) / 1024
                        # 파일 크기를 KB로 계산합니다.
                        os.remove(f_path)
                        # 파일을 삭제합니다.
                        log(f"  [삭제] {f_path}  ({size_kb:.1f} KB)")
                        # 삭제 완료 로그를 출력합니다.
                    else:
                        # 파일이 없으면
                        log(f"  [없음] {f_path}")
                        # 파일이 없다고 로그합니다.
                except Exception as cleanup_err:
                    # 삭제 실패 시
                    log(f"  [삭제실패] {f_path}: {cleanup_err}")
                    # 실패 로그를 출력합니다.
        else:
            # 보존 모드면 (개발/디버깅용)
            log("[*] 생성된 파일 목록 (CLEANUP_IMAGE_FILE=false, 보존 모드):")
            # 생성된 파일 목록 출력 시작을 로그합니다.
            for f_path in files_to_cleanup:
                # 정리 대상 파일들을 반복합니다.
                if os.path.exists(f_path):
                    # 파일이 존재하면
                    size_kb = os.path.getsize(f_path) / 1024
                    # 파일 크기를 KB로 계산합니다.
                    log(f"  [보존] {f_path}  ({size_kb:.1f} KB)")
                    # 파일을 보존한다고 로그합니다.
                else:
                    # 파일이 없으면
                    log(f"  [없음] {f_path}")
                    # 파일이 없다고 로그합니다.


# ──────────────────────────────────────────────────────────────────────────────
# 신규: scan_reports 레코드 생성 함수
# ──────────────────────────────────────────────────────────────────────────────
def build_scan_report(
    filtered_data: dict,
    scan_job_id,
    user_id: str,
    image_tag: str,
    report_path=None
) -> dict:
    """
    filtered_data 의 grype_vulnerabilities / trivy_vulnerabilities 전체 리스트를
    직접 사용하여 scan_reports 테이블에 저장할 통계를 계산합니다.
    """

    # 도구별 { vulnerability_id → severity } 매핑을 전체 리스트에서 직접 구성
    grype_map: dict[str, str] = {}
    # Grype 도구의 취약점 매핑을 초기화합니다.
    trivy_map: dict[str, str] = {}
    # Trivy 도구의 취약점 매핑을 초기화합니다.

    for v in filtered_data.get("grype_vulnerabilities", []):
        # Grype 전체 취약점 리스트를 순회합니다.
        vid = (v.get("vulnerability_id") or "").strip().upper()
        # 취약점 ID를 대문자로 정규화합니다. (DB 컬럼명: vulnerability_id)
        if not vid:
            # 취약점 ID가 없으면 건너뜁니다.
            continue
        sev = normalize_severity(v.get("severity"))
        # 심각도를 5개 표준값으로 정규화합니다.
        grype_map.setdefault(vid, sev)
        # 중복은 무시하고 첫 등장만 기록합니다.

    for v in filtered_data.get("trivy_vulnerabilities", []):
        # Trivy 전체 취약점 리스트를 순회합니다.
        vid = (v.get("vulnerability_id") or "").strip().upper()
        # 취약점 ID를 대문자로 정규화합니다. (DB 컬럼명: vulnerability_id)
        if not vid:
            # 취약점 ID가 없으면 건너뜁니다.
            continue
        sev = normalize_severity(v.get("severity"))
        # 심각도를 5개 표준값으로 정규화합니다.
        trivy_map.setdefault(vid, sev)
        # 중복은 무시하고 첫 등장만 기록합니다.

    grype_ids = set(grype_map.keys())
    # Grype의 취약점 ID 집합을 생성합니다.
    trivy_ids  = set(trivy_map.keys())
    # Trivy의 취약점 ID 집합을 생성합니다.
    common_ids = grype_ids & trivy_ids
    # 공통 취약점 ID 집합을 생성합니다.

    # 심각도 불일치 (같은 취약점 ID인데 두 도구의 등급이 다른 경우)
    mismatch_ids = {
        # 심각도가 다른 취약점 ID를 찾습니다.
        vid for vid in common_ids
        # 공통 취약점 ID 중에서
        if grype_map[vid] != trivy_map[vid]
        # Grype와 Trivy의 심각도가 다르면
    }

    total_count    = len(grype_ids | trivy_ids)
    # 전체 고유 취약점 수를 계산합니다.
    common_count   = len(common_ids)
    # 공통 취약점 수를 계산합니다.
    grype_only     = len(grype_ids - trivy_ids)
    # Grype 전용 취약점 수를 계산합니다.
    trivy_only     = len(trivy_ids - grype_ids)
    # Trivy 전용 취약점 수를 계산합니다.
    mismatch_count = len(mismatch_ids)
    # 심각도 불일치 수를 계산합니다.

    now = datetime.now(timezone.utc).isoformat()
    # 현재 시각을 ISO 형식으로 기록합니다.

    return {
        # scan_reports 레코드를 반환합니다.
        "id":             str(uuid.uuid4()),
        # scan_reports.id (Primary)를 생성합니다.
        "user_id":        user_id,
        # scan_reports.user_id를 설정합니다.
        "scan_job_id":    scan_job_id,
        # scan_reports.scan_job_id를 설정합니다.
        "scan_jobs_id":   scan_job_id,
        # scan_reports.scan_jobs_id를 동일 값으로 설정합니다.
        "image_tag":      image_tag,
        # scan_reports.image_tag를 설정합니다.
        "total_count":    total_count,
        # scan_reports.total_count를 설정합니다.
        "common_count":   common_count,
        # scan_reports.common_count를 설정합니다.
        "grype_only":     grype_only,
        # scan_reports.grype_only를 설정합니다.
        "trivy_only":     trivy_only,
        # scan_reports.trivy_only를 설정합니다.
        "mismatch_count": mismatch_count,
        # scan_reports.mismatch_count를 설정합니다.
        "report_path":    report_path,
        # scan_reports.report_path를 설정합니다.
        "created_at":     now
        # scan_reports.created_at를 설정합니다.
    }


# ──────────────────────────────────────────────────────────────────────────────
# 보조 함수 1: 심각도별 취약점 개수 집계 (분류별)
# ──────────────────────────────────────────────────────────────────────────────
def count_by_severity(filtered_data: dict) -> dict:
    # 분류별 심각도 집계를 계산합니다.
    severity_counts = {
        # 심각도별 개수를 저장할 딕셔너리입니다.
        "grype_only":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        # Grype only 취약점의 심각도 분포입니다.
        "trivy_only":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        # Trivy only 취약점의 심각도 분포입니다.
        "mismatch":       {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        # Mismatch 취약점의 심각도 분포입니다.
        "common_matched": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        # 두 도구가 동일 심각도로 일치 탐지한 취약점의 분포입니다.
    }

    def _bump(category: str, sev: str) -> None:
        # 분류와 심각도를 받아 카운트를 1 증가시키는 헬퍼입니다.
        if sev in severity_counts[category]:
            # 알려진 심각도면
            severity_counts[category][sev] += 1
            # 해당 심각도 카운트를 증가시킵니다.
        else:
            # 알려지지 않은 심각도면
            severity_counts[category]["UNKNOWN"] += 1
            # UNKNOWN 카운트를 증가시킵니다.

    # Grype only 취약점 심각도 집계
    for v in filtered_data.get("grype_only", []):
        # Grype only 취약점에 대해 반복합니다.
        sev = normalize_severity(v.get("severity"))
        # 심각도를 5개 표준값으로 정규화합니다.
        _bump("grype_only", sev)
        # grype_only 분류로 카운트합니다.

    # Trivy only 취약점 심각도 집계
    for v in filtered_data.get("trivy_only", []):
        # Trivy only 취약점에 대해 반복합니다.
        sev = normalize_severity(v.get("severity"))
        # 심각도를 5개 표준값으로 정규화합니다.
        _bump("trivy_only", sev)
        # trivy_only 분류로 카운트합니다.

    # Mismatch 취약점 심각도 집계 (Grype 기준 심각도 사용)
    for v in filtered_data.get("mismatch", []):
        # Mismatch 취약점에 대해 반복합니다.
        sev = normalize_severity(v.get("severity"))
        # 심각도를 5개 표준값으로 정규화합니다.
        _bump("mismatch", sev)
        # mismatch 분류로 카운트합니다.

    # Common matched (두 도구가 동일 심각도로 일치 탐지) 집계
    grype_sev_map = {
        (v.get("vulnerability_id") or "").strip().upper(): normalize_severity(v.get("severity"))
        for v in filtered_data.get("grype_vulnerabilities", [])
        if v.get("vulnerability_id")
    }
    # Grype 취약점의 ID→심각도 맵을 만듭니다.
    trivy_sev_map = {
        (v.get("vulnerability_id") or "").strip().upper(): normalize_severity(v.get("severity"))
        for v in filtered_data.get("trivy_vulnerabilities", [])
        if v.get("vulnerability_id")
    }
    # Trivy 취약점의 ID→심각도 맵을 만듭니다.

    common_ids = set(grype_sev_map.keys()) & set(trivy_sev_map.keys())
    # 두 도구가 모두 탐지한 공통 취약점 ID 집합입니다.
    for vid in common_ids:
        # 공통 취약점 ID들을 순회합니다.
        if grype_sev_map[vid] == trivy_sev_map[vid]:
            # 심각도가 일치하면
            _bump("common_matched", grype_sev_map[vid])
            # common_matched 분류로 카운트합니다.

    return severity_counts
    # 분류별 심각도 집계를 반환합니다.




# ──────────────────────────────────────────────────────────────────────────────
# 보조 함수 3: Grype + Trivy 결과 정제 (3가지 분류)
# ──────────────────────────────────────────────────────────────────────────────
def filter_results(grype_data: dict, trivy_data: dict) -> dict:
    # 취약점을 저장할 임시 딕셔너리 초기화
    grype_vulns = {}
    # Grype 취약점을 {CVE_ID: 취약점_정보} 형태로 저장합니다.
    trivy_vulns = {}
    # Trivy 취약점을 {CVE_ID: 취약점_정보} 형태로 저장합니다.
    
    processed = {
        # 최종 결과를 저장할 딕셔너리입니다.
        "grype_only": [],
        # Grype만 찾은 취약점들입니다.
        "trivy_only": [],
        # Trivy만 찾은 취약점들입니다.
        "mismatch": [],
        # Grype와 Trivy가 모두 찾았지만 심각도가 다른 취약점들입니다.
        "secrets": []
        # Trivy가 찾은 시크릿들입니다.
    }

    # ── 단계 1: Grype 결과 처리 ─────────────────────────────────────────────────
    for match in grype_data.get("matches", []):
        # Grype 결과의 각 매칭에 대해 반복합니다.
        vuln = match.get("vulnerability", {})
        # 취약점 정보를 추출합니다.
        art  = match.get("artifact", {})
        # 아티팩트(패키지) 정보를 추출합니다.

        vuln_id = vuln.get("id")
        # 취약점 ID를 추출합니다.
        pkg_name = art.get("name")
        # 패키지명을 추출합니다.

        # NOT NULL 필수 필드(vulnerability_id, package_name) 검증 - 없으면 skip
        if not vuln_id or not pkg_name:
            # 필수 필드가 없으면
            continue
            # 다음 매칭으로 진행합니다. (DB INSERT 실패 방지)

        cvss     = vuln.get("cvss", [])
        # CVSS 점수 정보를 추출합니다.
        risk     = cvss[0].get("metrics", {}).get("baseScore", "N/A") if cvss else "N/A"
        # 기본 CVSS 점수를 추출합니다.
        related  = match.get("relatedVulnerabilities", [])
        # 관련 취약점 정보를 추출합니다.
        related_id = related[0].get("id") if related else None
        # 첫 번째 관련 취약점의 ID를 추출합니다.
        fix_info  = vuln.get("fix", {})
        # 수정 정보를 추출합니다.
        fix_state = fix_info.get("state", "not-fixed")
        # 수정 상태를 추출합니다.
        # 빈 문자열은 None 으로 변환 (DB 의 is_fixed_available 자동 계산 호환)
        fix_version_str = ", ".join(fix_info.get("versions", []))
        # 수정 버전을 콤마로 연결합니다.
        if not fix_version_str.strip():
            # 빈 문자열이면
            fix_version_str = None
            # None 으로 변환합니다.

        grype_vulns[vuln_id] = {
            # Grype 취약점 정보를 저장합니다. (DB 컬럼명에 맞게 키 변경)
            "source":                  "grype",
            # 도구 출처를 grype으로 표시합니다.
            "vulnerability_id":        vuln_id,
            # 취약점 ID입니다. (DB 컬럼: grype_filtered.vulnerability_id)
            "data_source":             vuln.get("dataSource"),
            # 데이터 출처입니다. (DB 컬럼: grype_filtered.data_source)
            "description":             vuln.get("description"),
            # 취약점 설명입니다.
            "fix_version":             fix_version_str,
            # 수정된 버전들입니다. (빈 문자열 → None)
            "state":                   fix_state,
            # 수정 상태입니다.
            "is_fixed_available":      fix_state == "fixed",
            # 수정이 가능한지 여부입니다.
            "artifact_id":             art.get("id"),
            # 아티팩트 ID입니다. (DB 컬럼: grype_filtered.artifact_id)
            "package_name":            pkg_name,
            # 패키지 이름입니다.
            "package_type":            art.get("type"),
            # 패키지 유형입니다.
            "install_path":            art.get("locations", [{}])[0].get("realPath")
                                       if art.get("locations") else None,
            # 설치 경로입니다.
            "severity":                normalize_severity(vuln.get("severity")),
            # 심각도입니다. (DB CHECK 제약: 5개 표준값으로 정규화)
            "risk":                    risk,
            # 위험 점수입니다. (DB 컬럼: grype_filtered.risk)
            "version":                 art.get("version"),
            # 패키지 버전입니다.
            "related_vulnerability_id": related_id,
            # 관련 취약점 ID입니다.
        }

    # ── 단계 2: Trivy 결과 처리 ─────────────────────────────────────────────────
    if "Results" in trivy_data:
        # Trivy 결과가 있으면
        for result in trivy_data["Results"]:
            # 각 결과에 대해 반복합니다.
            target    = result.get("Target")
            # 대상 이미지를 추출합니다.
            res_class = result.get("Class")
            # 결과 클래스를 추출합니다.
            res_type  = result.get("Type")
            # 결과 타입을 추출합니다.

            for v in result.get("Vulnerabilities", []):
                # 각 취약점에 대해 반복합니다.
                vuln_id = v.get("VulnerabilityID")
                # 취약점 ID를 추출합니다.
                pkg_name = v.get("PkgName")
                # 패키지명을 추출합니다.

                # NOT NULL 필수 필드(vulnerability_id, package_name) 검증 - 없으면 skip
                if not vuln_id or not pkg_name:
                    # 필수 필드가 없으면
                    continue
                    # 다음 취약점으로 진행합니다. (DB INSERT 실패 방지)

                fixed_ver = v.get("FixedVersion")
                # 수정된 버전을 추출합니다.
                # 빈 문자열은 None 으로 변환 (DB 의 is_fixed_available 자동 계산 호환)
                if fixed_ver is not None and not str(fixed_ver).strip():
                    # 빈 문자열이면
                    fixed_ver = None
                    # None 으로 변환합니다.
                
                trivy_vulns[vuln_id] = {
                    # Trivy 취약점 정보를 저장합니다. (DB 컬럼명에 맞게 키 변경)
                    "source":            "trivy",
                    # 도구 출처를 trivy로 표시합니다.
                    "target":            target,
                    # 대상 이미지입니다.
                    "result_class":      res_class,
                    # 결과 클래스입니다.
                    "result_type":       res_type,
                    # 결과 타입입니다.
                    "vulnerability_id":  vuln_id,
                    # 취약점 ID입니다. (DB 컬럼: application_filtered.vulnerability_id)
                    "package_name":      pkg_name,
                    # 패키지 이름입니다.
                    "package_path":      v.get("PkgPath"),
                    # 패키지 경로입니다.
                    "installed_version": v.get("InstalledVersion"),
                    # 설치된 버전입니다.
                    "fixed_version":     fixed_ver,
                    # 수정된 버전입니다.
                    "is_fixed_available": bool(fixed_ver),
                    # 수정이 가능한지 여부입니다.
                    "severity":          normalize_severity(v.get("Severity")),
                    # 심각도입니다. (DB CHECK 제약: 5개 표준값으로 정규화)
                    "primary_url":       v.get("PrimaryURL"),
                    # 주요 URL입니다.
                    "title":             v.get("Title"),
                    # 제목입니다.
                    "description":       v.get("Description"),
                    # 설명입니다.
                }

            for s in result.get("Secrets", []):
                # 각 시크릿에 대해 반복합니다.
                rule_id = s.get("RuleID")
                # 규칙 ID를 추출합니다.
                # NOT NULL 필수 필드(rule_id) 검증 - 없으면 skip
                if not rule_id:
                    # rule_id 가 없으면
                    continue
                    # 다음 시크릿으로 진행합니다. (DB INSERT 실패 방지)

                processed["secrets"].append({
                    # 시크릿 정보를 추가합니다.
                    "source":      "trivy",
                    "title":        s.get("Title"),
                    # 시크릿 제목입니다. (참고: DB 에 title 컬럼은 없으나 백엔드 참고용으로 보존)
                    "rule_id":      rule_id,
                    # 규칙 ID입니다.
                    "severity":     normalize_severity(s.get("Severity")),
                    # 심각도입니다. (5개 표준값으로 정규화)
                    "match_text":   s.get("Match"),
                    # 매칭된 텍스트입니다.
                    "category":     s.get("Category"),
                    # 카테고리입니다.
                    "layer_digest": s.get("Layer", {}).get("Digest"),
                    # 레이어 다이제스트입니다.
                    "diff_id":      s.get("Layer", {}).get("DiffID"),
                    # Diff ID입니다.
                    "created_by":   s.get("Layer", {}).get("CreatedBy")
                    # 생성자입니다.
                })

    # ── 단계 3: 취약점 분류 (Grype Only, Trivy Only, Mismatch) ──────────────────
    grype_ids = set(grype_vulns.keys())
    # Grype 취약점 ID 집합을 만듭니다.
    trivy_ids = set(trivy_vulns.keys())
    # Trivy 취약점 ID 집합을 만듭니다.
    
    grype_only_ids = grype_ids - trivy_ids
    # Grype만 찾은 취약점 ID들입니다.
    trivy_only_ids = trivy_ids - grype_ids
    # Trivy만 찾은 취약점 ID들입니다.
    common_ids = grype_ids & trivy_ids
    # 공통으로 찾은 취약점 ID들입니다.

    # Grype only 취약점 추가
    for vuln_id in grype_only_ids:
        # Grype만 찾은 각 취약점에 대해 반복합니다.
        processed["grype_only"].append(grype_vulns[vuln_id])
        # Grype only 리스트에 추가합니다.

    # Trivy only 취약점 추가
    for vuln_id in trivy_only_ids:
        # Trivy만 찾은 각 취약점에 대해 반복합니다.
        processed["trivy_only"].append(trivy_vulns[vuln_id])
        # Trivy only 리스트에 추가합니다.

    # Mismatch 취약점 추가 (심각도가 다른 경우)
    for vuln_id in common_ids:
        # 공통으로 찾은 각 취약점에 대해 반복합니다.
        grype_sev = grype_vulns[vuln_id].get("severity", "UNKNOWN")
        # Grype의 심각도를 추출합니다. (이미 normalize_severity 통과)
        trivy_sev = trivy_vulns[vuln_id].get("severity", "UNKNOWN")
        # Trivy의 심각도를 추출합니다. (이미 normalize_severity 통과)
        
        if grype_sev != trivy_sev:
            # 심각도가 다르면
            mismatch_entry = grype_vulns[vuln_id].copy()
            # Grype 정보를 기반으로 시작합니다.
            mismatch_entry["grype_severity"] = grype_sev
            # Grype 심각도를 추가합니다.
            mismatch_entry["trivy_severity"] = trivy_sev
            # Trivy 심각도를 추가합니다.
            mismatch_entry["trivy_data"] = trivy_vulns[vuln_id]
            # Trivy 정보도 함께 추가합니다.
            processed["mismatch"].append(mismatch_entry)
            # Mismatch 리스트에 추가합니다.

    # ── 메인 데이터: Grype 전체 (OS 취약점), Trivy 전체 (App 취약점) ─────────────
    # Grype가 발견한 OS 취약점 전체 리스트
    processed["grype_vulnerabilities"] = list(grype_vulns.values())
    # Trivy가 발견한 App 취약점 전체 리스트
    processed["trivy_vulnerabilities"] = list(trivy_vulns.values())

    # ── 부가 데이터: 교차 분석용 (grype_only + trivy_only + mismatch 합본) ────────
    processed["vulnerabilities"] = (
        processed["grype_only"] +
        processed["trivy_only"] +
        processed["mismatch"]
    )

    return processed
    # 처리된 결과를 반환합니다.


# ──────────────────────────────────────────────────────────────────────────────
# 유틸리티: JSON 파일 저장 헬퍼
# ──────────────────────────────────────────────────────────────────────────────
def _dump(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        # 파일을 쓰기 모드로 엽니다.
        json.dump(data, f, indent=4, ensure_ascii=False)
        # 데이터를 JSON으로 변환하여 파일에 씁니다.

# ══════════════════════════════════════════════════════════════════════════════
# PDF 보고서 생성 기능 (추가 모듈)
# 
# [흐름]
# Frontend → API Server → DB 조회 (report_path NULL 확인)
#                       ↓ NULL이면
#                  Python /report/generate 호출 (여기!)
#                       ↓
#         Python이 Supabase DB 조회 + PDF 생성 + Storage 업로드
#                       ↓
#                  storage_path 반환
#                       ↓
#         API Server가 scan_reports.report_path 업데이트 + Signed URL 반환
#                       ↓
#                  Frontend가 PDF 다운로드
#
# [필수 환경변수]
#   SUPABASE_URL          - Supabase 프로젝트 URL
#   SUPABASE_SERVICE_KEY  - service_role 키 (관리자 권한)
#   SUPABASE_BUCKET       - Storage 버킷명 (기본: reports)
#
# [필수 라이브러리]
#   pip install supabase weasyprint
# ══════════════════════════════════════════════════════════════════════════════

from collections import Counter
# 패키지별 취약점 개수 카운트에 사용합니다.

# ──────────────────────────────────────────────
# Supabase / Storage 설정
# ──────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://zyppdhjjetyogpuvjafp.supabase.co")
# Supabase 프로젝트 URL입니다.
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp5cHBkaGpqZXR5b2dwdXZqYWZwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NjkwMzA0MiwiZXhwIjoyMDkyNDc5MDQyfQ.8Ea6x9eETyO9SX2FqGi_t9OfarvAzPk3-mKCXFZBJkg")
# Supabase service_role 키입니다. (관리자 권한, 외부 노출 금지)
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "reports")
# PDF를 저장할 Storage 버킷명입니다.

# Supabase 클라이언트는 lazy 초기화 (서버 시작 시 키가 없어도 다른 기능 동작 보장)
_supabase_client = None
# 전역 클라이언트 변수입니다.


def get_supabase_client():
    """
    Supabase 클라이언트를 lazy 초기화로 가져옵니다.
    환경변수가 없으면 None을 반환하여 호출부에서 에러 처리하게 합니다.
    """
    global _supabase_client
    # 전역 변수에 접근합니다.
    if _supabase_client is not None:
        # 이미 초기화되어 있으면 캐시된 클라이언트를 반환합니다.
        return _supabase_client
    if not SUPABASE_URL or not SUPABASE_KEY:
        # 환경변수가 없으면
        log("[!] SUPABASE_URL 또는 SUPABASE_SERVICE_KEY 환경변수가 없습니다.")
        return None
    try:
        # 클라이언트 생성을 시도합니다.
        from supabase import create_client
        # supabase 라이브러리를 임포트합니다. (pip install supabase)
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        log("[+] Supabase 클라이언트 초기화 완료")
        return _supabase_client
    except Exception as e:
        # 초기화 실패 시
        log(f"[!] Supabase 클라이언트 초기화 실패: {e}")
        return None


# ──────────────────────────────────────────────
# DB에서 보고서 데이터 조회
# ──────────────────────────────────────────────
async def fetch_report_data(scan_job_id: str) -> dict:
    """
    Supabase에서 scan_job_id 기준으로 보고서에 필요한 모든 데이터를 가져옵니다.
    조회 테이블: scan_jobs, scan_reports, OS_filtered, application_filtered,
                 security_filtered, grype_only, trivy_only, mismatch
    """
    sb = get_supabase_client()
    # Supabase 클라이언트를 가져옵니다.
    if sb is None:
        # 클라이언트가 없으면
        raise RuntimeError("Supabase 클라이언트를 사용할 수 없습니다.")

    loop = asyncio.get_event_loop()
    # 현재 이벤트 루프를 가져옵니다.

    def _query():
        # 동기 supabase-py 호출을 executor 안에서 실행합니다.
        # 1. scan_jobs (기본 정보)
        scan_job_res = sb.table("scan_jobs") \
            .select("*") \
            .eq("id", scan_job_id) \
            .execute()

        # 2. scan_reports (통계)
        scan_report_res = sb.table("scan_reports") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 3. OS_filtered (Grype OS 취약점)
        os_res = sb.table("OS_filtered") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 4. application_filtered (Trivy 앱 취약점)
        app_res = sb.table("application_filtered") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 5. security_filtered (시크릿)
        sec_res = sb.table("security_filtered") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 6. grype_only
        grype_only_res = sb.table("grype_only") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 7. trivy_only
        trivy_only_res = sb.table("trivy_only") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        # 8. mismatch
        mismatch_res = sb.table("mismatch") \
            .select("*") \
            .eq("scan_job_id", scan_job_id) \
            .execute()

        return {
            "scan_job":    scan_job_res.data[0] if scan_job_res.data else {},
            "scan_report": scan_report_res.data[0] if scan_report_res.data else {},
            "os_vulns":    os_res.data or [],
            "app_vulns":   app_res.data or [],
            "secrets":     sec_res.data or [],
            "grype_only":  grype_only_res.data or [],
            "trivy_only":  trivy_only_res.data or [],
            "mismatch":    mismatch_res.data or [],
        }

    return await loop.run_in_executor(None, _query)


# ──────────────────────────────────────────────
# HTML 빌드 헬퍼: 심각도 배지
# ──────────────────────────────────────────────
def _sev_badge(sev: str) -> str:
    """심각도에 따라 색깔 있는 HTML 배지를 생성합니다."""
    sev_u = (sev or "UNKNOWN").upper()
    # 심각도를 대문자로 변환합니다.
    sev_l = sev_u.lower()
    # CSS 클래스용 소문자입니다.
    return f'<span class="sev sev-{sev_l}">{sev_u}</span>'


# ──────────────────────────────────────────────
# HTML 보고서 빌드 (DB 데이터 기반)
# ──────────────────────────────────────────────
def build_report_html(data: dict) -> str:
    """
    DB에서 가져온 데이터를 받아 PDF용 HTML 문자열을 생성합니다.
    """
    scan_job    = data.get("scan_job", {}) or {}
    scan_report = data.get("scan_report", {}) or {}
    os_vulns    = data.get("os_vulns", []) or []
    app_vulns   = data.get("app_vulns", []) or []
    secrets     = data.get("secrets", []) or []
    grype_only  = data.get("grype_only", []) or []
    trivy_only  = data.get("trivy_only", []) or []
    mismatch    = data.get("mismatch", []) or []

    # ── 통계 계산 ──────────────────────────────────────────────────
    all_vulns = os_vulns + app_vulns
    # OS 취약점 + App 취약점 통합 리스트입니다.
    total    = len(all_vulns)
    critical = sum(1 for v in all_vulns if (v.get("severity") or "").upper() == "CRITICAL")
    high     = sum(1 for v in all_vulns if (v.get("severity") or "").upper() == "HIGH")
    medium   = sum(1 for v in all_vulns if (v.get("severity") or "").upper() == "MEDIUM")
    low      = sum(1 for v in all_vulns if (v.get("severity") or "").upper() == "LOW")
    unknown  = sum(1 for v in all_vulns if (v.get("severity") or "").upper() == "UNKNOWN")

    def pct(n):
        # 0 나누기 방지하면서 백분율 계산
        return (n / total * 100) if total > 0 else 0

    # ── 패키지별 취약점 개수 Top 10 ────────────────────────────────
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    pkg_counter      = Counter()
    pkg_max_severity = {}
    pkg_versions     = {}
    pkg_fix_versions = {}

    for v in all_vulns:
        pkg = v.get("package_name") or "unknown"
        pkg_counter[pkg] += 1
        cur_sev = (v.get("severity") or "UNKNOWN").upper()
        if pkg not in pkg_max_severity or \
           severity_rank.get(cur_sev, 0) > severity_rank.get(pkg_max_severity[pkg], 0):
            pkg_max_severity[pkg] = cur_sev
        # OS_filtered는 version / fix_version, application_filtered는 installed_version / fixed_version
        ver = v.get("version") or v.get("installed_version") or "-"
        fix = v.get("fix_version") or v.get("fixed_version") or "-"
        pkg_versions[pkg]     = ver
        pkg_fix_versions[pkg] = fix

    top10_pkgs = pkg_counter.most_common(10)
    # 상위 10개 패키지를 추출합니다.

    # ── 메타 정보 ──────────────────────────────────────────────────
    image_name = scan_job.get("image_name") or scan_job.get("file_name") or "unknown"
    scan_id    = scan_job.get("id") or "unknown"
    created_at_raw = scan_job.get("created_at") or ""
    created_at = created_at_raw[:16].replace("T", " ") if created_at_raw else ""

    # ── 비교 통계 ──────────────────────────────────────────────────
    common_count   = scan_report.get("common_count", 0)
    grype_only_cnt = scan_report.get("grype_only", len(grype_only))
    trivy_only_cnt = scan_report.get("trivy_only", len(trivy_only))
    mismatch_cnt   = scan_report.get("mismatch_count", len(mismatch))

    # ── Top 10 패키지 행 ───────────────────────────────────────────
    pkg_rows_html = ""
    for i, (pkg, cnt) in enumerate(top10_pkgs, 1):
        pkg_rows_html += f"""
        <tr>
          <td>{i}</td>
          <td><strong>{pkg}</strong></td>
          <td class="mono">{pkg_versions.get(pkg, "-")}</td>
          <td class="mono">{pkg_fix_versions.get(pkg, "-")}</td>
          <td>{cnt}</td>
          <td>{_sev_badge(pkg_max_severity.get(pkg, "UNKNOWN"))}</td>
        </tr>
        """

    # ── Critical 앱 취약점 행 (최대 10개) ───────────────────────────
    critical_apps = [v for v in app_vulns if (v.get("severity") or "").upper() == "CRITICAL"][:10]
    critical_rows_html = ""
    for v in critical_apps:
        title_or_desc = (v.get("title") or v.get("description") or "")[:80]
        critical_rows_html += f"""
        <tr>
          <td class="mono">{v.get('vulnerability_id', '-')}</td>
          <td>{v.get('package_name', '-')}</td>
          <td class="mono">{v.get('installed_version', '-')}</td>
          <td class="mono">{v.get('fixed_version', '-') or '-'}</td>
          <td>{title_or_desc}</td>
        </tr>
        """
    if not critical_rows_html:
        critical_rows_html = '<tr><td colspan="5" style="text-align:center;color:#6b7280;">Critical 앱 취약점이 없습니다.</td></tr>'

    # ── Mismatch 행 (최대 5개) ──────────────────────────────────────
    mismatch_rows_html = ""
    for v in mismatch[:5]:
        g_sev = (v.get("grype_severity") or "UNKNOWN").upper()
        t_sev = (v.get("trivy_severity") or "UNKNOWN").upper()
        rec   = g_sev if severity_rank.get(g_sev, 0) >= severity_rank.get(t_sev, 0) else t_sev
        mismatch_rows_html += f"""
        <tr>
          <td class="mono">{v.get('vulnerability_id', '-')}</td>
          <td>{v.get('package_name', '-')}</td>
          <td>{_sev_badge(g_sev)}</td>
          <td>{_sev_badge(t_sev)}</td>
          <td>{_sev_badge(rec)}</td>
        </tr>
        """
    if not mismatch_rows_html:
        mismatch_rows_html = '<tr><td colspan="5" style="text-align:center;color:#6b7280;">Mismatch 항목이 없습니다.</td></tr>'

    # ── OS 취약점 행 (최대 10개, 심각도 내림차순) ───────────────────
    os_sorted = sorted(
        os_vulns,
        key=lambda x: severity_rank.get((x.get("severity") or "UNKNOWN").upper(), 0),
        reverse=True
    )[:10]
    os_rows_html = ""
    for v in os_sorted:
        os_rows_html += f"""
        <tr>
          <td class="mono">{v.get('vulnerability_id', '-')}</td>
          <td>{v.get('package_name', '-')}</td>
          <td>{_sev_badge((v.get('severity') or 'UNKNOWN').upper())}</td>
          <td>{v.get('state', '-') or '-'}</td>
          <td class="mono">{v.get('fix_version', '-') or '-'}</td>
        </tr>
        """
    if not os_rows_html:
        os_rows_html = '<tr><td colspan="5" style="text-align:center;color:#6b7280;">OS 취약점이 없습니다.</td></tr>'

    # ── 시크릿 집계 ────────────────────────────────────────────────
    secret_summary = Counter()
    secret_layer   = {}
    for s in secrets:
        key = (s.get("rule_id") or "-", s.get("category") or "-", (s.get("severity") or "UNKNOWN").upper())
        secret_summary[key] += 1
        if key not in secret_layer:
            ld = s.get("layer_digest") or ""
            secret_layer[key] = (ld[:20] + "...") if ld else "-"

    secrets_rows_html = ""
    for (rule_id, category, sev), cnt in secret_summary.items():
        secrets_rows_html += f"""
        <tr>
          <td>{rule_id}</td>
          <td>{category}</td>
          <td>{_sev_badge(sev)}</td>
          <td>{cnt}</td>
          <td class="mono">{secret_layer.get((rule_id, category, sev), '-')}</td>
        </tr>
        """
    if not secrets_rows_html:
        secrets_rows_html = '<tr><td colspan="5" style="text-align:center;color:#6b7280;">탐지된 시크릿이 없습니다.</td></tr>'

    # ── 최종 HTML 조립 ─────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>Container Security Report</title>
<style>
  @page {{ size: A4; margin: 20mm 15mm;
    @bottom-center {{ content: "Page " counter(page) " / " counter(pages); font-size: 9pt; color: #888; }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Noto Sans KR', 'Malgun Gothic', sans-serif; font-size: 10pt; color: #1a1a1a; line-height: 1.5; }}
  .cover {{ page-break-after: always; height: 257mm; background: #1e3a8a; color: white; padding: 50px 40px; margin: -20mm -15mm 0 -15mm; position: relative; }}
  .cover-tag {{ font-size: 11pt; letter-spacing: 4px; text-transform: uppercase; opacity: 0.7; margin-top: 60px; }}
  .cover-title {{ font-size: 36pt; font-weight: 800; line-height: 1.2; margin-top: 20px; }}
  .cover-subtitle {{ font-size: 14pt; opacity: 0.85; margin-top: 12px; }}
  .cover-meta {{ position: absolute; bottom: 60px; left: 40px; right: 40px; border-top: 1px solid rgba(255,255,255,0.3); padding-top: 24px; font-size: 11pt; }}
  .cover-meta div {{ margin-bottom: 6px; }}
  .cover-meta strong {{ display: inline-block; width: 120px; opacity: 0.7; }}
  section {{ margin-bottom: 28px; }}
  h2 {{ font-size: 16pt; font-weight: 700; border-left: 4px solid #1e3a8a; padding-left: 12px; margin-bottom: 14px; color: #1e3a8a; }}
  h3 {{ font-size: 12pt; font-weight: 600; margin: 16px 0 8px; color: #374151; }}
  .kpi-row {{ display: flex; gap: 8px; margin-bottom: 16px; }}
  .kpi {{ flex: 1; border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px 6px; text-align: center; background: #fafafa; }}
  .kpi-label {{ font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; color: #6b7280; margin-bottom: 4px; }}
  .kpi-value {{ font-size: 20pt; font-weight: 800; }}
  .kpi.total .kpi-value {{ color: #1e3a8a; }}
  .kpi.critical {{ background: #fef2f2; border-color: #fecaca; }}
  .kpi.critical .kpi-value {{ color: #dc2626; }}
  .kpi.high {{ background: #fff7ed; border-color: #fed7aa; }}
  .kpi.high .kpi-value {{ color: #ea580c; }}
  .kpi.medium {{ background: #fefce8; border-color: #fde68a; }}
  .kpi.medium .kpi-value {{ color: #ca8a04; }}
  .kpi.low {{ background: #f0fdf4; border-color: #bbf7d0; }}
  .kpi.low .kpi-value {{ color: #16a34a; }}
  .kpi.unknown {{ background: #f3f4f6; }}
  .kpi.unknown .kpi-value {{ color: #6b7280; }}
  .compare-row {{ display: flex; gap: 10px; margin-top: 8px; }}
  .compare-card {{ flex: 1; border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px; text-align: center; }}
  .compare-card .num {{ font-size: 22pt; font-weight: 800; color: #1e3a8a; }}
  .compare-card .label {{ font-size: 8.5pt; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
  .compare-card.warn .num {{ color: #f59e0b; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 9pt; margin-top: 8px; }}
  th {{ background: #1e3a8a; color: white; padding: 8px 10px; text-align: left; font-weight: 600; font-size: 8.5pt; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #fafbfc; }}
  td.mono {{ font-family: Consolas, monospace; font-size: 8.5pt; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 8pt; font-weight: 700; text-transform: uppercase; color: white; }}
  .sev-critical {{ background: #dc2626; }}
  .sev-high {{ background: #ea580c; }}
  .sev-medium {{ background: #ca8a04; }}
  .sev-low {{ background: #16a34a; }}
  .sev-unknown {{ background: #6b7280; }}
  .page-break {{ page-break-before: always; }}
  .text-muted {{ color: #4b5563; font-size: 9.5pt; }}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-tag">Container Security Report</div>
  <div class="cover-title">취약점 분석 보고서</div>
  <div class="cover-subtitle">{image_name}</div>
  <div class="cover-meta">
    <div><strong>Scan ID</strong> {scan_id}</div>
    <div><strong>Image</strong> {image_name}</div>
    <div><strong>Scanners</strong> Grype + Trivy</div>
    <div><strong>Generated</strong> {created_at}</div>
  </div>
</div>

<!-- 1. EXECUTIVE SUMMARY -->
<section>
  <h2>1. Executive Summary</h2>
  <div class="kpi-row">
    <div class="kpi total"><div class="kpi-label">Total</div><div class="kpi-value">{total}</div></div>
    <div class="kpi critical"><div class="kpi-label">Critical</div><div class="kpi-value">{critical}</div></div>
    <div class="kpi high"><div class="kpi-label">High</div><div class="kpi-value">{high}</div></div>
    <div class="kpi medium"><div class="kpi-label">Medium</div><div class="kpi-value">{medium}</div></div>
    <div class="kpi low"><div class="kpi-label">Low</div><div class="kpi-value">{low}</div></div>
    <div class="kpi unknown"><div class="kpi-label">Unknown</div><div class="kpi-value">{unknown}</div></div>
  </div>
  <p class="text-muted">
    총 <strong>{total}</strong>건의 취약점이 발견되었으며, 즉시 조치가 필요한 Critical {critical}건, High {high}건이 포함됩니다.
    탐지된 시크릿은 {len(secrets)}건입니다.
  </p>
</section>

<!-- 2. SCANNER COMPARISON -->
<section>
  <h2>2. Scanner Comparison</h2>
  <div class="compare-row">
    <div class="compare-card"><div class="num">{common_count}</div><div class="label">Common</div></div>
    <div class="compare-card"><div class="num">{grype_only_cnt}</div><div class="label">Grype Only</div></div>
    <div class="compare-card"><div class="num">{trivy_only_cnt}</div><div class="label">Trivy Only</div></div>
    <div class="compare-card warn"><div class="num">{mismatch_cnt}</div><div class="label">Mismatch</div></div>
  </div>

  <h3>심각도 불일치 (Severity Mismatch)</h3>
  <table>
    <thead>
      <tr><th>CVE</th><th>Package</th><th>Grype</th><th>Trivy</th><th>Recommended</th></tr>
    </thead>
    <tbody>
      {mismatch_rows_html}
    </tbody>
  </table>
</section>

<!-- 3. TOP 10 PACKAGES -->
<section class="page-break">
  <h2>3. Top 10 Vulnerable Packages</h2>
  <p class="text-muted">중복 카운트 기준으로 가장 많은 취약점이 집중된 패키지입니다.</p>
  <table>
    <thead>
      <tr><th>#</th><th>Package</th><th>Current</th><th>Fixed</th><th>Count</th><th>Max Severity</th></tr>
    </thead>
    <tbody>
      {pkg_rows_html if pkg_rows_html else '<tr><td colspan="6" style="text-align:center;color:#6b7280;">패키지 데이터가 없습니다.</td></tr>'}
    </tbody>
  </table>
</section>

<!-- 4. CRITICAL APP VULNERABILITIES -->
<section class="page-break">
  <h2>4. Application Critical Vulnerabilities</h2>
  <table>
    <thead>
      <tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Description</th></tr>
    </thead>
    <tbody>
      {critical_rows_html}
    </tbody>
  </table>
</section>

<!-- 5. SECRETS -->
<section>
  <h2>5. Secrets & Sensitive Data</h2>
  <table>
    <thead>
      <tr><th>Rule ID</th><th>Category</th><th>Severity</th><th>Count</th><th>Layer</th></tr>
    </thead>
    <tbody>
      {secrets_rows_html}
    </tbody>
  </table>
</section>

<!-- 6. OS PACKAGE VULNERABILITIES -->
<section>
  <h2>6. OS Package Vulnerabilities</h2>
  <table>
    <thead>
      <tr><th>CVE</th><th>Package</th><th>Severity</th><th>State</th><th>Fix Version</th></tr>
    </thead>
    <tbody>
      {os_rows_html}
    </tbody>
  </table>
</section>

<div style="margin-top:40px;text-align:center;font-size:8.5pt;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:14px;">
  본 보고서는 자동 생성되었습니다. · Scan ID: {scan_id} · {created_at}
</div>

</body>
</html>"""
    return html


def _summarize_report_data(data: dict) -> dict:
    """Prepare a compact summary that can be rendered by multiple PDF engines."""
    scan_job = data.get("scan_job", {}) or {}
    scan_report = data.get("scan_report", {}) or {}
    os_vulns = data.get("os_vulns", []) or []
    app_vulns = data.get("app_vulns", []) or []
    secrets = data.get("secrets", []) or []
    grype_only = data.get("grype_only", []) or []
    trivy_only = data.get("trivy_only", []) or []
    mismatch = data.get("mismatch", []) or []

    all_vulns = os_vulns + app_vulns
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    severity_counts = {key: 0 for key in severity_rank}

    pkg_counter = Counter()
    pkg_max_severity = {}
    pkg_versions = {}
    pkg_fix_versions = {}

    for vuln in all_vulns:
        severity = normalize_severity(vuln.get("severity"))
        severity_counts[severity] += 1

        pkg = vuln.get("package_name") or "unknown"
        pkg_counter[pkg] += 1

        if severity_rank.get(severity, 0) > severity_rank.get(pkg_max_severity.get(pkg, "UNKNOWN"), 0):
            pkg_max_severity[pkg] = severity

        pkg_versions[pkg] = vuln.get("version") or vuln.get("installed_version") or "-"
        pkg_fix_versions[pkg] = vuln.get("fix_version") or vuln.get("fixed_version") or "-"

    top_packages = []
    for pkg, count in pkg_counter.most_common(10):
        top_packages.append({
            "package": pkg,
            "count": count,
            "severity": pkg_max_severity.get(pkg, "UNKNOWN"),
            "version": pkg_versions.get(pkg, "-"),
            "fixed_version": pkg_fix_versions.get(pkg, "-"),
        })

    critical_apps = []
    for vuln in app_vulns:
        if normalize_severity(vuln.get("severity")) != "CRITICAL":
            continue
        critical_apps.append({
            "id": vuln.get("vulnerability_id", "-"),
            "package": vuln.get("package_name", "-"),
            "version": vuln.get("installed_version", "-"),
            "fix": vuln.get("fixed_version") or "-",
            "description": (vuln.get("title") or vuln.get("description") or "-").strip(),
        })
    critical_apps = critical_apps[:10]

    os_top = []
    for vuln in sorted(
        os_vulns,
        key=lambda item: severity_rank.get(normalize_severity(item.get("severity")), 0),
        reverse=True,
    )[:10]:
        os_top.append({
            "id": vuln.get("vulnerability_id", "-"),
            "package": vuln.get("package_name", "-"),
            "severity": normalize_severity(vuln.get("severity")),
            "state": vuln.get("state") or "-",
            "fix": vuln.get("fix_version") or "-",
        })

    secret_counts = Counter()
    secret_layers = {}
    for secret in secrets:
        key = (
            secret.get("rule_id") or "-",
            secret.get("category") or "-",
            normalize_severity(secret.get("severity")),
        )
        secret_counts[key] += 1
        if key not in secret_layers:
            digest = secret.get("layer_digest") or "-"
            secret_layers[key] = digest[:20] + "..." if digest not in {"", "-"} and len(digest) > 20 else digest

    secret_summary = []
    for (rule_id, category, severity), count in secret_counts.most_common(10):
        secret_summary.append({
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "count": count,
            "layer": secret_layers.get((rule_id, category, severity), "-"),
        })

    mismatch_top = []
    for vuln in mismatch[:10]:
        grype_severity = normalize_severity(vuln.get("grype_severity"))
        trivy_severity = normalize_severity(vuln.get("trivy_severity"))
        recommended = (
            grype_severity
            if severity_rank.get(grype_severity, 0) >= severity_rank.get(trivy_severity, 0)
            else trivy_severity
        )
        mismatch_top.append({
            "id": vuln.get("vulnerability_id", "-"),
            "package": vuln.get("package_name", "-"),
            "grype": grype_severity,
            "trivy": trivy_severity,
            "recommended": recommended,
        })

    created_at_raw = scan_job.get("created_at") or ""
    created_at = created_at_raw[:19].replace("T", " ") if created_at_raw else "-"

    return {
        "scan_id": scan_job.get("id") or "-",
        "image_name": scan_job.get("image_name") or scan_job.get("file_name") or "unknown",
        "created_at": created_at,
        "total": len(all_vulns),
        "severity_counts": severity_counts,
        "common_count": scan_report.get("common_count", 0),
        "grype_only_count": scan_report.get("grype_only", len(grype_only)),
        "trivy_only_count": scan_report.get("trivy_only", len(trivy_only)),
        "mismatch_count": scan_report.get("mismatch_count", len(mismatch)),
        "secret_count": len(secrets),
        "top_packages": top_packages,
        "critical_apps": critical_apps,
        "os_top": os_top,
        "secret_summary": secret_summary,
        "mismatch_top": mismatch_top,
    }


def _register_reportlab_fonts() -> tuple[str, str]:
    """Register a Windows font with Korean coverage when available."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular_name = "Helvetica"
    bold_name = "Helvetica-Bold"

    font_candidates = [
        ("MalgunGothic", r"C:\Windows\Fonts\malgun.ttf"),
        ("MalgunGothicBold", r"C:\Windows\Fonts\malgunbd.ttf"),
    ]

    for font_name, font_path in font_candidates:
        if not os.path.exists(font_path):
            continue
        if font_name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(font_name, font_path))

    if "MalgunGothic" in pdfmetrics.getRegisteredFontNames():
        regular_name = "MalgunGothic"
    if "MalgunGothicBold" in pdfmetrics.getRegisteredFontNames():
        bold_name = "MalgunGothicBold"
    elif regular_name == "MalgunGothic":
        bold_name = regular_name

    return regular_name, bold_name


def _build_pdf_with_reportlab(data: dict, pdf_local_path: str) -> None:
    """Generate a compact PDF without native GTK dependencies."""
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    summary = _summarize_report_data(data)
    font_name, font_bold = _register_reportlab_fonts()

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DSPTitle",
        parent=styles["Title"],
        fontName=font_bold,
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#1e3a8a"),
        spaceAfter=10,
    )
    heading_style = ParagraphStyle(
        "DSPHeading",
        parent=styles["Heading2"],
        fontName=font_bold,
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=10,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "DSPBody",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#111827"),
        spaceAfter=4,
    )
    small_style = ParagraphStyle(
        "DSPSmall",
        parent=body_style,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#6b7280"),
    )
    table_header_style = ParagraphStyle(
        "DSPTableHeader",
        parent=body_style,
        fontName=font_bold,
        textColor=colors.white,
        alignment=1,
    )

    def p(text: str, style=body_style) -> Paragraph:
        return Paragraph(escape(str(text if text not in (None, "") else "-")), style)

    def build_table(rows: list[list], col_widths=None) -> Table:
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), font_bold),
                    ("FONTNAME", (0, 1), (-1, -1), font_name),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def page_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font_name, 8)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        pdf_local_path,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=16 * mm,
        bottomMargin=14 * mm,
    )

    story = [
        Paragraph("Container Security Report", title_style),
        p(f"Image: {summary['image_name']}"),
        p(f"Scan ID: {summary['scan_id']}"),
        p(f"Generated: {summary['created_at']}"),
        Spacer(1, 8),
        Paragraph("1. Executive Summary", heading_style),
    ]

    severity_counts = summary["severity_counts"]
    summary_table = [
        [Paragraph("Metric", table_header_style), Paragraph("Count", table_header_style)],
        [p("Total"), p(summary["total"])],
        [p("Critical"), p(severity_counts["CRITICAL"])],
        [p("High"), p(severity_counts["HIGH"])],
        [p("Medium"), p(severity_counts["MEDIUM"])],
        [p("Low"), p(severity_counts["LOW"])],
        [p("Unknown"), p(severity_counts["UNKNOWN"])],
        [p("Secrets"), p(summary["secret_count"])],
    ]
    story.append(build_table(summary_table, col_widths=[70 * mm, 25 * mm]))
    story.append(Spacer(1, 8))

    comparison_table = [
        [
            Paragraph("Common", table_header_style),
            Paragraph("Grype Only", table_header_style),
            Paragraph("Trivy Only", table_header_style),
            Paragraph("Mismatch", table_header_style),
        ],
        [
            p(summary["common_count"]),
            p(summary["grype_only_count"]),
            p(summary["trivy_only_count"]),
            p(summary["mismatch_count"]),
        ],
    ]
    story.append(Paragraph("2. Scanner Comparison", heading_style))
    story.append(build_table(comparison_table, col_widths=[38 * mm, 38 * mm, 38 * mm, 38 * mm]))
    story.append(Spacer(1, 8))

    mismatch_rows = [[
        Paragraph("CVE", table_header_style),
        Paragraph("Package", table_header_style),
        Paragraph("Grype", table_header_style),
        Paragraph("Trivy", table_header_style),
        Paragraph("Recommended", table_header_style),
    ]]
    for item in summary["mismatch_top"]:
        mismatch_rows.append([
            p(item["id"], small_style),
            p(item["package"]),
            p(item["grype"]),
            p(item["trivy"]),
            p(item["recommended"]),
        ])
    if len(mismatch_rows) == 1:
        mismatch_rows.append([p("No severity mismatches found.")] + [p("") for _ in range(4)])
    story.append(build_table(mismatch_rows, col_widths=[36 * mm, 42 * mm, 24 * mm, 24 * mm, 28 * mm]))
    story.append(PageBreak())

    top_pkg_rows = [[
        Paragraph("#", table_header_style),
        Paragraph("Package", table_header_style),
        Paragraph("Current", table_header_style),
        Paragraph("Fixed", table_header_style),
        Paragraph("Count", table_header_style),
        Paragraph("Max Severity", table_header_style),
    ]]
    for idx, item in enumerate(summary["top_packages"], 1):
        top_pkg_rows.append([
            p(idx),
            p(item["package"]),
            p(item["version"], small_style),
            p(item["fixed_version"], small_style),
            p(item["count"]),
            p(item["severity"]),
        ])
    if len(top_pkg_rows) == 1:
        top_pkg_rows.append([p("No vulnerable packages found.")] + [p("") for _ in range(5)])
    story.append(Paragraph("3. Top Vulnerable Packages", heading_style))
    story.append(build_table(top_pkg_rows, col_widths=[10 * mm, 42 * mm, 25 * mm, 25 * mm, 15 * mm, 25 * mm]))
    story.append(Spacer(1, 8))

    critical_rows = [[
        Paragraph("CVE", table_header_style),
        Paragraph("Package", table_header_style),
        Paragraph("Version", table_header_style),
        Paragraph("Fix", table_header_style),
        Paragraph("Description", table_header_style),
    ]]
    for item in summary["critical_apps"]:
        critical_rows.append([
            p(item["id"], small_style),
            p(item["package"]),
            p(item["version"], small_style),
            p(item["fix"], small_style),
            p(item["description"]),
        ])
    if len(critical_rows) == 1:
        critical_rows.append([p("No critical application vulnerabilities found.")] + [p("") for _ in range(4)])
    story.append(Paragraph("4. Critical Application Vulnerabilities", heading_style))
    story.append(build_table(critical_rows, col_widths=[30 * mm, 28 * mm, 20 * mm, 20 * mm, 70 * mm]))
    story.append(PageBreak())

    secret_rows = [[
        Paragraph("Rule ID", table_header_style),
        Paragraph("Category", table_header_style),
        Paragraph("Severity", table_header_style),
        Paragraph("Count", table_header_style),
        Paragraph("Layer", table_header_style),
    ]]
    for item in summary["secret_summary"]:
        secret_rows.append([
            p(item["rule_id"]),
            p(item["category"]),
            p(item["severity"]),
            p(item["count"]),
            p(item["layer"], small_style),
        ])
    if len(secret_rows) == 1:
        secret_rows.append([p("No secrets found.")] + [p("") for _ in range(4)])
    story.append(Paragraph("5. Secrets and Sensitive Data", heading_style))
    story.append(build_table(secret_rows, col_widths=[28 * mm, 40 * mm, 24 * mm, 18 * mm, 48 * mm]))
    story.append(Spacer(1, 8))

    os_rows = [[
        Paragraph("CVE", table_header_style),
        Paragraph("Package", table_header_style),
        Paragraph("Severity", table_header_style),
        Paragraph("State", table_header_style),
        Paragraph("Fix Version", table_header_style),
    ]]
    for item in summary["os_top"]:
        os_rows.append([
            p(item["id"], small_style),
            p(item["package"]),
            p(item["severity"]),
            p(item["state"]),
            p(item["fix"], small_style),
        ])
    if len(os_rows) == 1:
        os_rows.append([p("No OS vulnerabilities found.")] + [p("") for _ in range(4)])
    story.append(Paragraph("6. Top OS Vulnerabilities", heading_style))
    story.append(build_table(os_rows, col_widths=[34 * mm, 42 * mm, 24 * mm, 26 * mm, 34 * mm]))
    story.append(Spacer(1, 8))
    story.append(p(f"Generated automatically for scan job {summary['scan_id']}.", small_style))

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)


def _generate_pdf_document(report_data: dict, html_string: str, pdf_local_path: str) -> str:
    """Try the existing HTML renderer first, then fall back to ReportLab on Windows."""
    try:
        from weasyprint import HTML

        HTML(string=html_string).write_pdf(pdf_local_path)
        return "weasyprint"
    except Exception as weasy_error:
        log(
            f"[!] WeasyPrint PDF 생성 실패, ReportLab으로 대체합니다: "
            f"{type(weasy_error).__name__}: {str(weasy_error)[:200]}"
        )

    try:
        _build_pdf_with_reportlab(report_data, pdf_local_path)
        return "reportlab"
    except Exception as reportlab_error:
        raise RuntimeError(
            "PDF generation failed with both WeasyPrint and ReportLab: "
            f"{type(reportlab_error).__name__}: {str(reportlab_error)}"
        ) from reportlab_error


# ──────────────────────────────────────────────
# PDF 생성 + Storage 업로드 엔드포인트
# 호출 주체: Node.js API Server (내부 통신만 허용 권장)
# ──────────────────────────────────────────────
@app.post("/report/generate")
async def generate_report_endpoint(request: Request):
    """
    요청 body (JSON):
      { "scan_job_id": "<UUID>" }
    
    동작 순서:
      1. DB에서 스캔 관련 데이터 조회
      2. HTML 빌드
      3. WeasyPrint로 PDF 생성
      4. Supabase Storage에 업로드
      5. storage_path를 응답으로 반환
    
    응답:
      { "status": "success", "storage_path": "<scan_job_id>/report.pdf" }
    """
    try:
        body = await request.json()
        # 요청 본문을 파싱합니다.
        scan_job_id = body.get("scan_job_id")
        # 스캔 작업 ID를 추출합니다.

        if not scan_job_id:
            # ID가 없으면
            return {"status": "error", "detail": "scan_job_id is required"}

        log(f"[*] PDF 보고서 생성 시작: scan_job_id={scan_job_id}")

        # ── 1단계: DB에서 데이터 조회 ──────────────────────────────
        report_data = await fetch_report_data(scan_job_id)
        # Supabase에서 모든 관련 데이터를 가져옵니다.

        if not report_data.get("scan_job"):
            # scan_jobs 레코드가 없으면
            log(f"[!] scan_job_id에 해당하는 데이터 없음: {scan_job_id}")
            return {"status": "error", "detail": "scan job not found"}

        log(
            f"[+] DB 조회 완료: "
            f"OS={len(report_data['os_vulns'])} / "
            f"App={len(report_data['app_vulns'])} / "
            f"Secrets={len(report_data['secrets'])} / "
            f"Mismatch={len(report_data['mismatch'])}"
        )

        # ── 2단계: HTML 빌드 ───────────────────────────────────────
        html_string = build_report_html(report_data)
        # DB 데이터로 HTML을 만듭니다.
        log(f"[+] HTML 빌드 완료 ({len(html_string)} bytes)")

        # ── 3단계: PDF 생성 (WeasyPrint, 블로킹이므로 executor 사용) ─
        pdf_local_path = work_path(f"report_{scan_job_id}.pdf")
        # 임시 PDF 파일 경로입니다.

        loop = asyncio.get_event_loop()
        # 현재 이벤트 루프를 가져옵니다.

        def _make_pdf():
            return _generate_pdf_document(report_data, html_string, pdf_local_path)

        pdf_engine = await loop.run_in_executor(None, _make_pdf)
        # 블로킹 호출을 스레드풀에서 실행합니다.
        log(f"[+] PDF 생성 완료 ({pdf_engine}): {pdf_local_path}")

        # ── 4단계: Supabase Storage에 업로드 ──────────────────────
        sb = get_supabase_client()
        if sb is None:
            # 클라이언트가 없으면
            return {
                "status": "error",
                "detail": "Supabase client not configured (check SUPABASE_URL / SUPABASE_SERVICE_KEY)"
            }

        storage_path = f"{scan_job_id}/report.pdf"
        # Storage 내 저장 경로 (버킷 안 경로) 입니다.

        with open(pdf_local_path, "rb") as f:
            # 생성된 PDF를 바이너리로 읽습니다.
            pdf_bytes = f.read()

        def _upload():
            # Supabase Storage 업로드를 동기 호출합니다.
            # upsert=true 로 동일 경로 덮어쓰기를 허용합니다.
            return sb.storage.from_(SUPABASE_BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={
                    "content-type": "application/pdf",
                    "upsert": "true"
                }
            )

        try:
            await loop.run_in_executor(None, _upload)
            log(f"[+] Storage 업로드 완료: {SUPABASE_BUCKET}/{storage_path}")
        except Exception as upload_err:
            # 업로드 실패 시
            log(f"[!] Storage 업로드 실패: {upload_err}")
            return {"status": "error", "detail": f"upload failed: {upload_err}"}

        # ── 5단계: 임시 로컬 PDF 삭제 (Storage에 이미 있으므로 불필요) ─
        try:
            os.remove(pdf_local_path)
            # 로컬 임시 파일을 삭제합니다.
            log(f"  [삭제] {pdf_local_path}")
        except Exception:
            pass
            # 삭제 실패는 조용히 무시합니다.

        # ── 6단계: 응답 반환 ───────────────────────────────────────
        # API Server가 이 storage_path를 받아
        # 1) scan_reports.report_path 업데이트
        # 2) Signed URL 생성 후 프론트로 전달
        return {
            "status": "success",
            "scan_job_id": scan_job_id,
            "storage_path": storage_path,
            "bucket": SUPABASE_BUCKET
        }

    except Exception as e:
        # 전체 예외 처리
        log(f"[!] PDF 생성 중 예외 발생: {type(e).__name__}: {str(e)[:500]}")
        return {"status": "error", "detail": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# PDF 생성 기능 끝
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# 서버 실행 진입점
# Windows: python test03.py  또는  uvicorn test03:app --host 0.0.0.0 --port 8000
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 이 파일이 직접 실행되면
    import uvicorn
    # uvicorn 모듈을 임포트합니다.
    uvicorn.run(app, host="0.0.0.0", port=8000)
    # FastAPI 애플리케이션을 실행합니다.
