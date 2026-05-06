import subprocess   # 외부 보안 도구(Syft, Grype, Trivy)를 실행합니다.
import json          # JSON 파싱 및 저장에 사용합니다.
import os            # 파일 경로 생성, 존재 확인, 삭제 등에 사용합니다.
import uuid          # scan_reports.id 등 UUID 생성에 사용합니다.
import asyncio       # 블로킹 subprocess를 스레드풀에서 실행하기 위해 사용합니다.
import sys           # 로그 즉시 출력(flush)에 사용합니다.
import requests      # 분석 결과를 API 서버로 HTTP 전송할 때 사용합니다.
from datetime import datetime, timezone   # UTC 기준 시각 기록에 사용합니다.
from fastapi import FastAPI, UploadFile, File, Form  # 웹 API 구성에 사용합니다.

app = FastAPI()  # FastAPI 애플리케이션 인스턴스를 생성합니다.

# ──────────────────────────────────────────────
# Windows 환경 설정
# - Windows의 경우 syft/grype/trivy가 PATH에 있으면 바로 실행되지만,
#   명시적으로 설치 경로를 지정할 수 있습니다.
# - 아래 TOOL_* 변수를 실제 설치 경로로 변경하세요.
#   예) C:\Program Files\syft\syft.exe  또는  syft (PATH에 등록된 경우)
# ──────────────────────────────────────────────
TOOL_SYFT  = os.environ.get("SYFT_PATH",  "syft")
# Windows 환경에서는 환경 변수로 SYFT_PATH를 설정하거나 기본값 사용합니다.
TOOL_GRYPE = os.environ.get("GRYPE_PATH", "grype")
# Windows 환경에서는 환경 변수로 GRYPE_PATH를 설정하거나 기본값 사용합니다.
TOOL_TRIVY = os.environ.get("TRIVY_PATH", "trivy")
# Windows 환경에서는 환경 변수로 TRIVY_PATH를 설정하거나 기본값 사용합니다.

# 임시 파일 저장 디렉터리 (Windows에서는 %TEMP% 폴더 사용)
WORK_DIR = os.environ.get("SCANNER_WORK_DIR", os.path.abspath("."))
# 환경 변수가 없으면 현재 디렉토리를 사용합니다.
os.makedirs(WORK_DIR, exist_ok=True)
# WORK_DIR이 없으면 생성합니다.

# API 서버 주소 설정
API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://localhost:8080")
# 환경 변수로 API 서버 주소를 설정하거나 기본값을 사용합니다.
API_SAVE_ENDPOINT = f"{API_SERVER_URL}/save"
# API 서버의 저장 엔드포인트 주소입니다.
API_TIMEOUT = 30
# API 요청 타임아웃을 30초로 설정합니다.

# 임시 이미지 파일 자동 삭제 여부 (운영: True 권장, 개발 디버깅: False)
CLEANUP_IMAGE_FILE = os.environ.get("CLEANUP_IMAGE_FILE", "true").lower() == "true"
# 환경 변수로 이미지 파일 삭제 여부를 제어합니다.


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
            return True
            # True를 반환합니다.
        else:
            # 실패 상태 코드면
            log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
            # 실패 로그와 응답 텍스트를 출력합니다.
            return False
            # False를 반환합니다.
            
    except requests.exceptions.Timeout:
        # 타임아웃 예외 발생 시
        log(f"[!] API 서버 요청 타임아웃 ({API_TIMEOUT}초)")
        # 타임아웃 로그를 출력합니다.
        return False
        # False를 반환합니다.
    except requests.exceptions.ConnectionError:
        # 연결 실패 예외 발생 시
        log(f"[!] API 서버 연결 실패: {endpoint}")
        # 연결 실패 로그를 출력합니다.
        return False
        # False를 반환합니다.
    except Exception as e:
        # 기타 예외 발생 시
        log(f"[!] API 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        # 예외 정보를 로그에 출력합니다.
        return False
        # False를 반환합니다.


async def send_all_files_to_api(
    payload: dict,
    json_files: dict,
    endpoint: str = None
) -> bool:
    """
    모든 JSON 파일을 포함하여 API 서버로 전송합니다.
    payload: 최종 payload 데이터입니다.
    json_files: {파일_이름: 파일_경로} 형식의 JSON 파일 딕셔너리입니다.
    endpoint: API 엔드포인트 URL입니다 (기본값: API_SAVE_ENDPOINT).
    반환값: True(성공) / False(실패)
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
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(
                endpoint,
                files=files,
                data=data,
                timeout=API_TIMEOUT * 2  # 파일 전송은 더 긴 타임아웃
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
            return True
            # True를 반환합니다.
        else:
            # 실패 상태 코드면
            log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
            # 실패 로그와 응답 텍스트를 출력합니다.
            return False
            # False를 반환합니다.
            
    except requests.exceptions.Timeout:
        # 타임아웃 예외 발생 시
        log(f"[!] API 서버 요청 타임아웃 ({API_TIMEOUT * 2}초)")
        # 타임아웃 로그를 출력합니다.
        return False
        # False를 반환합니다.
    except requests.exceptions.ConnectionError:
        # 연결 실패 예외 발생 시
        log(f"[!] API 서버 연결 실패: {endpoint}")
        # 연결 실패 로그를 출력합니다.
        return False
        # False를 반환합니다.
    except Exception as e:
        # 기타 예외 발생 시
        log(f"[!] 파일 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        # 예외 정보를 로그에 출력합니다.
        return False
        # False를 반환합니다.


# ──────────────────────────────────────────────
# 메인 스캔 엔드포인트
# ──────────────────────────────────────────────
@app.post("/scan")
async def custom_scan_endpoint(
    user_id: str = Form(...),
    scan_name: str = Form(...),
    file: UploadFile = File(...)
):
    """
    [전체 흐름 요약]
    1. 업로드된 이미지를 임시 파일로 저장
    2. Syft  → SBOM(소프트웨어 구성 목록) 생성
    3. Grype → 패키지 취약점 스캔
    4. Trivy → 취약점 + 시크릿 정밀 분석
    5. 결과 정제 및 심각도별 카운트 집계
    6. scan_reports 레코드 생성 (Grype·Trivy 교차 분석)
    7. 최종 payload 구성 후 카테고리별 JSON 파일로 저장
    8. 임시 파일 전체 삭제 (finally 블록)
    """

    # ── 임시 파일 경로 정의 (WORK_DIR 기준, Windows 친화적) ──────────────────────
    safe_uid = user_id.replace("/", "_").replace("\\", "_")
    # Windows와 Linux 경로 구분자를 모두 언더스코어로 치환하여 경로 인젝션을 방지합니다.
    image_path    = work_path(f"temp_{safe_uid}_{file.filename}")
    # 업로드 이미지 파일의 임시 저장 경로입니다.
    syft_raw_file = work_path(f"syft_{safe_uid}.json")
    # Syft 실행 결과의 JSON 파일 경로입니다.
    trivy_raw_file= work_path(f"trivy_{safe_uid}.json")
    # Trivy 실행 결과의 JSON 파일 경로입니다.
    grype_raw_file= work_path(f"grype_{safe_uid}.json")
    # Grype 실행 결과의 JSON 파일 경로입니다.

    # 이미지 파일은 용량이 크므로 cleanup 대상에 포함합니다 (CLEANUP_IMAGE_FILE 환경변수로 제어).
    files_to_cleanup = [image_path]
    # 이미지 파일을 정리 대상으로 지정합니다.

    trivy_status = "pending"
    # Trivy 스캔 상태를 초기화합니다.
    grype_status = "pending"
    # Grype 스캔 상태를 초기화합니다.
    started_at   = datetime.now(timezone.utc).isoformat()
    # 스캔 시작 시각을 ISO 형식으로 기록합니다.

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

        # ── 단계 2: Syft 실행 ── SBOM 생성 ─────────────────────────────────────
        log(f"[*] 단계 1: Syft 실행 중 (사용자: {user_id})...")
        # Syft 실행 시작 로그를 출력합니다.
        syft_res = await run_tool([TOOL_SYFT, image_path, "-o", "cyclonedx-json"])
        # Syft를 실행하여 SBOM을 CycloneDX JSON 형식으로 생성합니다.
        if syft_res.returncode == 0 and syft_res.stdout:
            # Syft 실행이 성공하고 출력이 있으면
            syft_raw = json.loads(syft_res.stdout)
            # JSON 문자열을 파이썬 딕셔너리로 파싱합니다.
            with open(syft_raw_file, "w", encoding="utf-8") as f:
                # Syft 결과를 JSON 파일로 저장합니다.
                json.dump(syft_raw, f)
            log(f"[+] Syft 완료: {len(syft_raw.get('components', []))} 컴포넌트")
            # Syft 완료 로그와 컴포넌트 개수를 출력합니다.
        else:
            # Syft 실행이 실패하거나 출력이 없으면
            syft_raw = {}
            # 빈 딕셔너리를 사용합니다.
            log(f"[!] Syft 실패 (returncode={syft_res.returncode}): {syft_res.stderr[:300]}")
            # Syft 실패 로그와 에러 메시지의 처음 300자를 출력합니다.

        # ── 단계 3: Grype 실행 ── 패키지 취약점 스캔 ────────────────────────────
        log("[*] 단계 2: Grype 실행 중...")
        # Grype 실행 시작 로그를 출력합니다.
        grype_res = await run_tool([TOOL_GRYPE, image_path, "-o", "json"])
        # Grype를 실행하여 취약점을 JSON 형식으로 출력합니다.
        if grype_res.returncode == 0 and grype_res.stdout:
            # Grype 실행이 성공하고 출력이 있으면
            grype_raw    = json.loads(grype_res.stdout)
            # JSON 문자열을 파이썬 딕셔너리로 파싱합니다.
            grype_status = "success"
            # Grype 상태를 성공으로 업데이트합니다.
            with open(grype_raw_file, "w", encoding="utf-8") as f:
                # Grype 결과를 JSON 파일로 저장합니다.
                json.dump(grype_raw, f)
            log(f"[+] Grype 완료: {len(grype_raw.get('matches', []))} 매칭")
            # Grype 완료 로그와 매칭 개수를 출력합니다.
        else:
            # Grype 실행이 실패하거나 출력이 없으면
            grype_raw    = {}
            # 빈 딕셔너리를 사용합니다.
            grype_status = "failed"
            # Grype 상태를 실패로 업데이트합니다.
            log(f"[!] Grype 실패 (returncode={grype_res.returncode}): {grype_res.stderr[:300]}")
            # Grype 실패 로그와 에러 메시지의 처음 300자를 출력합니다.

        # ── 단계 4: Trivy 실행 ── 취약점 + 시크릿 정밀 분석 ────────────────────
        await ensure_trivy_db()
        # Trivy DB를 미리 다운로드합니다.
        log("[*] 단계 3: Trivy 실행 중...")
        # Trivy 실행 시작 로그를 출력합니다.
        trivy_res = await run_tool([
            # Trivy를 실행합니다.
            TOOL_TRIVY, "image",
            # 이미지 스캔 모드를 사용합니다.
            "--input", image_path,
            # 스캔할 이미지 경로를 지정합니다.
            "--format", "json",
            # JSON 형식의 출력을 지정합니다.
            "--scanners", "vuln,secret"
            # 취약점과 시크릿을 모두 스캔합니다.
        ])
        if trivy_res.returncode == 0 and trivy_res.stdout:
            # Trivy 실행이 성공하고 출력이 있으면
            trivy_raw    = json.loads(trivy_res.stdout)
            # JSON 문자열을 파이썬 딕셔너리로 파싱합니다.
            trivy_status = "success"
            # Trivy 상태를 성공으로 업데이트합니다.
            with open(trivy_raw_file, "w", encoding="utf-8") as f:
                # Trivy 결과를 JSON 파일로 저장합니다.
                json.dump(trivy_raw, f)
            log(f"[+] Trivy 완료: {len(trivy_raw.get('Results', []))} 결과 블록")
            # Trivy 완료 로그와 결과 블록 개수를 출력합니다.
        else:
            # Trivy 실행이 실패하거나 출력이 없으면
            trivy_raw    = {}
            # 빈 딕셔너리를 사용합니다.
            trivy_status = "failed"
            # Trivy 상태를 실패로 업데이트합니다.
            log(f"[!] Trivy 실패 (returncode={trivy_res.returncode}): {trivy_res.stderr[:300]}")
            # Trivy 실패 로그와 에러 메시지의 처음 300자를 출력합니다.

        # ── 단계 5: 데이터 정제 및 심각도 집계 ──────────────────────────────────
        filtered_data   = filter_results(grype_raw, trivy_data=trivy_raw)
        # Grype와 Trivy 결과를 정제합니다.
        severity_counts = count_by_severity(filtered_data)
        # 취약점을 심각도별로 집계합니다. (filtered_data dict 전달)
        finished_at     = datetime.now(timezone.utc).isoformat()
        # 스캔 완료 시각을 ISO 형식으로 기록합니다.

        # ── 단계 6: scan_reports 레코드 생성 (Grype·Trivy 교차 분석) ────────────
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

        # ── 단계 7: 최종 payload 구성 ────────────────────────────────────────────
        # ── 심각도 전체 합산 (scan_jobs 테이블용) ────────────────────────────────
        # 전체 고유 취약점 = grype + trivy 합집합 (mismatch / common 모두 포함)
        all_vuln_ids = set()
        for v in filtered_data.get("grype_vulnerabilities", []):
            vid = v.get("vulnerabilityid")
            if vid:
                all_vuln_ids.add(vid)
        for v in filtered_data.get("trivy_vulnerabilities", []):
            vid = v.get("vulnerabilityid")
            if vid:
                all_vuln_ids.add(vid)
        # 전체 고유 취약점 ID 집합을 만듭니다.

        def _total_sev(sev_key):
            return sum(
                severity_counts[cat].get(sev_key, 0)
                for cat in severity_counts
            )

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
                "image_name":            file.filename,
                # 이미지 이름입니다. (scan_jobs.image_name, image_tag 대신 수정)
                "status":                "success",
                # 전체 스캔 상태입니다.
                # syft_status 컬럼은 scan_jobs 스키마에 없으므로 제거
                "grype_status":          grype_status,
                # Grype 스캔 상태입니다.
                "trivy_status":          trivy_status,
                # Trivy 스캔 상태입니다.
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

        # ── 단계 8: API 서버로 모든 결과 전송 ───────────────────────────────────────
        log("[*] 단계 4: 모든 JSON 파일을 API 서버로 전송...")
        # API 전송 시작을 로그합니다.
        
        # 전송할 JSON 파일들을 정리
        json_files_to_send = {
            # 전송할 JSON 파일 딕셔너리입니다.
            "syft.json": syft_raw_file,
            # Syft 원본 결과 파일입니다.
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
        _dump(syft_raw_file, syft_raw)
        # Syft 원본 결과를 저장합니다.
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
        api_success = await send_all_files_to_api(final_payload, json_files_to_send)
        # 최종 payload와 모든 JSON 파일을 API 서버로 전송합니다.
        
        if api_success:
            # API 전송이 성공하면
            log("[+] API 서버 전송 완료")
            # 전송 완료 로그를 출력합니다.
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
                # 스캔 이름입니다.
                "file_name":     file.filename,
                # 파일명입니다.
                "status":        "failed",
                # 스캔 상태를 실패로 표시합니다.
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
    (기존: vulnerabilities 합본을 source로 분류 → mismatch 항목이 grype 쪽으로 편향되는 버그가 있어 수정)
    """

    # 도구별 { vulnerability_id → severity } 매핑을 전체 리스트에서 직접 구성
    grype_map: dict[str, str] = {}
    # Grype 도구의 취약점 매핑을 초기화합니다.
    trivy_map: dict[str, str] = {}
    # Trivy 도구의 취약점 매핑을 초기화합니다.

    for v in filtered_data.get("grype_vulnerabilities", []):
        # Grype 전체 취약점 리스트를 순회합니다.
        vid = (v.get("vulnerabilityid") or "").strip().upper()
        # 취약점 ID를 대문자로 정규화합니다.
        if not vid:
            # 취약점 ID가 없으면 건너뜁니다.
            continue
        sev = (v.get("severity") or "UNKNOWN").upper()
        # 심각도를 대문자로 정규화합니다.
        grype_map.setdefault(vid, sev)
        # 중복은 무시하고 첫 등장만 기록합니다.

    for v in filtered_data.get("trivy_vulnerabilities", []):
        # Trivy 전체 취약점 리스트를 순회합니다.
        vid = (v.get("vulnerabilityid") or "").strip().upper()
        # 취약점 ID를 대문자로 정규화합니다.
        if not vid:
            # 취약점 ID가 없으면 건너뜁니다.
            continue
        sev = (v.get("severity") or "UNKNOWN").upper()
        # 심각도를 대문자로 정규화합니다.
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
        sev = (v.get("severity") or "UNKNOWN").upper()
        # 심각도를 대문자로 정규화합니다.
        _bump("grype_only", sev)
        # grype_only 분류로 카운트합니다.

    # Trivy only 취약점 심각도 집계
    for v in filtered_data.get("trivy_only", []):
        # Trivy only 취약점에 대해 반복합니다.
        sev = (v.get("severity") or "UNKNOWN").upper()
        # 심각도를 대문자로 정규화합니다.
        _bump("trivy_only", sev)
        # trivy_only 분류로 카운트합니다.

    # Mismatch 취약점 심각도 집계 (Grype 기준 심각도 사용)
    for v in filtered_data.get("mismatch", []):
        # Mismatch 취약점에 대해 반복합니다.
        sev = (v.get("severity") or "UNKNOWN").upper()
        # 심각도를 대문자로 정규화합니다.
        _bump("mismatch", sev)
        # mismatch 분류로 카운트합니다.

    # Common matched (두 도구가 동일 심각도로 일치 탐지) 집계
    # → grype_vulnerabilities ∩ trivy_vulnerabilities 중 심각도가 같은 항목
    grype_sev_map = {
        (v.get("vulnerabilityid") or "").strip().upper(): (v.get("severity") or "UNKNOWN").upper()
        for v in filtered_data.get("grype_vulnerabilities", [])
        if v.get("vulnerabilityid")
    }
    # Grype 취약점의 ID→심각도 맵을 만듭니다.
    trivy_sev_map = {
        (v.get("vulnerabilityid") or "").strip().upper(): (v.get("severity") or "UNKNOWN").upper()
        for v in filtered_data.get("trivy_vulnerabilities", [])
        if v.get("vulnerabilityid")
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

        grype_vulns[vuln_id] = {
            # Grype 취약점 정보를 저장합니다.
            "source":                  "grype",
            # 도구 출처를 grype으로 표시합니다.
            "vulnerabilityid":         vuln_id,
            # 취약점 ID입니다.
            "dataSource":              vuln.get("dataSource"),
            # 데이터 출처입니다.
            "description":             vuln.get("description"),
            # 취약점 설명입니다.
            "fix_version":             ", ".join(fix_info.get("versions", [])),
            # 수정된 버전들입니다.
            "state":                   fix_state,
            # 수정 상태입니다.
            "is_fixed_available":      fix_state == "fixed",
            # 수정이 가능한지 여부입니다.
            "artifactid":              art.get("id"),
            # 아티팩트 ID입니다.
            "package_name":            art.get("name"),
            # 패키지 이름입니다.
            "package_type":            art.get("type"),
            # 패키지 유형입니다.
            "install_path":            art.get("locations", [{}])[0].get("realPath")
                                       if art.get("locations") else None,
            # 설치 경로입니다.
            "severity":                (vuln.get("severity") or "UNKNOWN").upper(),
            # 심각도입니다. (대소문자 정규화 → DB 일관성)
            "risk_score":              risk,
            # 위험 점수입니다.
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
                fixed_ver = v.get("FixedVersion")
                # 수정된 버전을 추출합니다.
                
                trivy_vulns[vuln_id] = {
                    # Trivy 취약점 정보를 저장합니다.
                    "source":            "trivy",
                    # 도구 출처를 trivy로 표시합니다.
                    "target":            target,
                    # 대상 이미지입니다.
                    "result_class":      res_class,
                    # 결과 클래스입니다.
                    "result_type":       res_type,
                    # 결과 타입입니다.
                    "vulnerabilityid":   vuln_id,
                    # 취약점 ID입니다.
                    "package_name":      v.get("PkgName"),
                    # 패키지 이름입니다.
                    "package_path":      v.get("PkgPath"),
                    # 패키지 경로입니다.
                    "installed_version": v.get("InstalledVersion"),
                    # 설치된 버전입니다.
                    "fixed_version":     fixed_ver,
                    # 수정된 버전입니다.
                    "is_fixed_available": bool(fixed_ver),
                    # 수정이 가능한지 여부입니다.
                    "severity":          (v.get("Severity") or "UNKNOWN").upper(),
                    # 심각도입니다. (대소문자 정규화)
                    "primary_url":       v.get("PrimaryURL"),
                    # 주요 URL입니다.
                    "title":             v.get("Title"),
                    # 제목입니다.
                    "description":       v.get("Description"),
                    # 설명입니다.
                }

            for s in result.get("Secrets", []):
                # 각 시크릿에 대해 반복합니다.
                processed["secrets"].append({
                    # 시크릿 정보를 추가합니다.
                    "title":        s.get("Title"),
                    # 시크릿 제목입니다.
                    "rule_id":      s.get("RuleID"),
                    # 규칙 ID입니다.
                    "severity":     s.get("Severity"),
                    # 심각도입니다.
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
        grype_sev = grype_vulns[vuln_id].get("severity", "UNKNOWN").upper()
        # Grype의 심각도를 추출합니다.
        trivy_sev = trivy_vulns[vuln_id].get("severity", "UNKNOWN").upper()
        # Trivy의 심각도를 추출합니다.
        
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
