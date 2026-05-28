# Supabase 로그인 페이지

`c:\project`에서 바로 실행 가능한 심플 로그인 웹페이지입니다.
기능: `로그인`, `회원가입`, `ID 찾기`, `P/W 찾기(재설정 메일 전송)`.
회원가입은 첫 화면에서 `회원가입` 버튼 클릭 시 추가정보 입력 영역이 열리는 방식입니다.

## 1) 설정

1. `config.example.js`를 `config.js`로 복사합니다.
2. `config.js`에 Supabase 값을 입력합니다.

```js
export const SUPABASE_URL = "https://YOUR_PROJECT_ID.supabase.co";
export const SUPABASE_ANON_KEY = "YOUR_SUPABASE_ANON_KEY";
```

## 2) 실행

브라우저에서 파일을 바로 여는 대신 로컬 서버로 실행하세요.

```powershell
cd c:\project
python -m http.server 5500
```

브라우저에서 `http://localhost:5500` 접속.

## 3) SQL 먼저 실행 (중요)

Supabase `SQL Editor`에서 [supabase_auth_setup.sql](C:/project/supabase_auth_setup.sql) 전체를 실행하세요.

생성 항목:
- `public.user_profiles` 테이블
- `auth.users` 연동 트리거
- RLS 정책
- ID/PW 찾기 RPC 함수

## 4) Supabase에서 필요한 값

- `Project URL` (`Settings > API`)
- `anon` key (`Settings > API`)

주의:
- `service_role` 키는 절대 프론트엔드에 넣으면 안 됩니다.

## 5) 필수 체크

- `Authentication > Providers > Email` 활성화
- 이메일 인증을 쓸지 여부 확인
  - 인증 ON이면 회원가입 후 메일 인증이 필요
  - 인증 OFF이면 회원가입 직후 로그인 세션 생성 가능
- `Authentication > URL Configuration` 에 `http://localhost:5500/` 추가
  - P/W 찾기에서 `resetPasswordForEmail` 동작에 필요

## 6) 회원가입 입력 규칙

- 로그인 ID: 영문 소문자/숫자/`_`, 4~20자
- 전화번호: 숫자만 10~11자리
- 생년월일: `YYYY-MM-DD`
