import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./config.js";

const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const signupLoginIdInput = document.getElementById("signup-login-id");
const signupFullNameInput = document.getElementById("signup-full-name");
const signupPhoneInput = document.getElementById("signup-phone");
const signupBirthDateInput = document.getElementById("signup-birth-date");
const signupExtra = document.getElementById("signup-extra");
const cancelSignupBtn = document.getElementById("cancel-signup-btn");

const loginBtn = document.getElementById("login-btn");
const signupBtn = document.getElementById("signup-btn");
const logoutBtn = document.getElementById("logout-btn");

const openIdFindBtn = document.getElementById("open-id-find");
const openPwFindBtn = document.getElementById("open-pw-find");

const idFindPanel = document.getElementById("id-find-panel");
const idFindNameInput = document.getElementById("id-find-name");
const idFindPhoneInput = document.getElementById("id-find-phone");
const idFindBirthInput = document.getElementById("id-find-birth");
const idFindBtn = document.getElementById("id-find-btn");
const idFindResult = document.getElementById("id-find-result");

const pwFindPanel = document.getElementById("pw-find-panel");
const pwFindLoginIdInput = document.getElementById("pw-find-login-id");
const pwFindPhoneInput = document.getElementById("pw-find-phone");
const pwFindBirthInput = document.getElementById("pw-find-birth");
const pwFindEmailInput = document.getElementById("pw-find-email");
const pwFindBtn = document.getElementById("pw-find-btn");
const pwFindResult = document.getElementById("pw-find-result");

const msgEl = document.getElementById("message");
const sessionBox = document.getElementById("session-box");
const userEmailEl = document.getElementById("user-email");
const controls = Array.from(document.querySelectorAll("button, input"));

const hasValidConfig =
  SUPABASE_URL &&
  SUPABASE_ANON_KEY &&
  !SUPABASE_URL.includes("YOUR_PROJECT_ID") &&
  !SUPABASE_ANON_KEY.includes("YOUR_SUPABASE_ANON_KEY");
let isBusy = false;
let isSignupMode = false;

if (!hasValidConfig) {
  showMessage("config.js 파일에 Supabase 키를 먼저 넣어주세요.", "err");
}

const supabase = hasValidConfig ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

function syncEnabledState() {
  const enabled = hasValidConfig && !isBusy;
  controls.forEach((el) => {
    el.disabled = !enabled;
  });
}

function showMessage(text, type = "") {
  msgEl.textContent = text;
  msgEl.className = `message ${type}`.trim();
}

function showInlineMessage(el, text, type = "") {
  el.textContent = text;
  el.className = `inline-message ${type}`.trim();
}

function setBusy(loading) {
  isBusy = loading;
  syncEnabledState();
  if (loading) {
    showMessage("처리 중...", "");
  }
}

function normalizePhone(phone) {
  return phone.replace(/\D/g, "");
}

function normalizeLoginId(loginId) {
  return loginId.trim().toLowerCase();
}

function isValidLoginId(loginId) {
  return /^[a-z0-9_]{4,20}$/.test(loginId);
}

function setSignupMode(enabled) {
  isSignupMode = enabled;
  signupExtra.classList.toggle("hidden", !enabled);
  signupBtn.textContent = enabled ? "회원가입 실행" : "회원가입";
  if (enabled) {
    showMessage("회원가입 모드입니다. 추가정보를 입력한 뒤 회원가입 실행을 눌러주세요.", "");
  }
}

function clearSignupExtraFields() {
  signupLoginIdInput.value = "";
  signupFullNameInput.value = "";
  signupPhoneInput.value = "";
  signupBirthDateInput.value = "";
}

function mapErrorMessage(error) {
  const msg = error?.message || "요청 처리 중 오류가 발생했습니다.";
  if (msg.includes("Invalid login credentials")) return "이메일 또는 비밀번호가 올바르지 않습니다.";
  if (msg.includes("Email not confirmed")) return "이메일 인증 후 로그인해 주세요.";
  if (msg.includes("User already registered")) return "이미 가입된 이메일입니다.";
  if (
    msg.includes("duplicate key value") &&
    (msg.includes("user_profiles_login_id_key") || msg.includes("profiles_login_id_key"))
  ) {
    return "이미 사용 중인 로그인 ID입니다.";
  }
  if (
    msg.includes("duplicate key value") &&
    (msg.includes("user_profiles_phone_key") || msg.includes("profiles_phone_key"))
  ) {
    return "이미 등록된 전화번호입니다.";
  }
  if (
    msg.includes("duplicate key value") &&
    (msg.includes("user_profiles_email_key") || msg.includes("profiles_email_key"))
  ) {
    return "이미 등록된 이메일입니다.";
  }
  if (msg.includes("Database error saving new user")) {
    return "회원가입 정보 저장 중 오류가 발생했습니다. 입력값을 확인해 주세요.";
  }
  if (msg.includes("Failed to fetch")) {
    return "네트워크 연결을 확인해 주세요.";
  }
  return msg;
}

function togglePanel(panelEl) {
  const targetIsHidden = panelEl.classList.contains("hidden");
  idFindPanel.classList.add("hidden");
  pwFindPanel.classList.add("hidden");
  if (targetIsHidden) {
    panelEl.classList.remove("hidden");
  }
}

async function runWithButtonBusy(button, busyText, action) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = busyText;
  try {
    await action();
  } finally {
    button.textContent = original;
    button.disabled = !hasValidConfig || isBusy;
  }
}

function renderSession(session) {
  if (session?.user?.email) {
    userEmailEl.textContent = session.user.email;
    sessionBox.classList.remove("hidden");
  } else {
    userEmailEl.textContent = "";
    sessionBox.classList.add("hidden");
  }
}

async function initializeSession() {
  if (!supabase) return;
  const { data, error } = await supabase.auth.getSession();
  if (error) {
    showMessage(error.message, "err");
    return;
  }
  renderSession(data.session);
}

async function signIn() {
  if (!supabase) return;
  setBusy(true);
  try {
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      showMessage("이메일과 비밀번호를 입력해 주세요.", "err");
      return;
    }

    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      showMessage(mapErrorMessage(error), "err");
    } else {
      showMessage("로그인 성공!", "ok");
    }
  } catch (error) {
    showMessage(mapErrorMessage(error), "err");
  } finally {
    setBusy(false);
  }
}

async function signUp() {
  if (!isSignupMode) {
    setSignupMode(true);
    return;
  }
  if (!supabase) {
    showMessage("Supabase 연결 설정을 확인해 주세요.", "err");
    return;
  }
  setBusy(true);
  try {
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const loginId = normalizeLoginId(signupLoginIdInput.value);
    const fullName = signupFullNameInput.value.trim();
    const phone = normalizePhone(signupPhoneInput.value);
    const birthDate = signupBirthDateInput.value;

    if (!email || !password || !loginId || !fullName || !phone || !birthDate) {
      showMessage("회원가입은 모든 추가정보(로그인 ID, 이름, 전화번호, 생년월일)가 필요합니다.", "err");
      return;
    }

    if (!isValidLoginId(loginId)) {
      showMessage("로그인 ID 형식이 올바르지 않습니다. (영문 소문자/숫자/_ 4~20자)", "err");
      return;
    }

    if (phone.length < 10 || phone.length > 11) {
      showMessage("전화번호는 숫자 10~11자리로 입력해 주세요.", "err");
      return;
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          login_id: loginId,
          full_name: fullName,
          phone,
          birth_date: birthDate
        }
      }
    });

    if (error) {
      showMessage(mapErrorMessage(error), "err");
    } else if (data?.user && Array.isArray(data.user.identities) && data.user.identities.length === 0) {
      showMessage(
        "이미 가입된 이메일일 수 있습니다. 이메일이 오지 않으면 기존 계정으로 로그인해 주세요.",
        "err"
      );
    } else if (!data.session) {
      showMessage("회원가입 완료. 이메일 인증 후 로그인해 주세요.", "ok");
      setSignupMode(false);
      clearSignupExtraFields();
    } else {
      showMessage("회원가입 및 로그인 성공!", "ok");
      setSignupMode(false);
      clearSignupExtraFields();
    }
  } catch (error) {
    showMessage(mapErrorMessage(error), "err");
  } finally {
    setBusy(false);
  }
}

async function signOut() {
  if (!supabase) return;
  setBusy(true);
  try {
    const { error } = await supabase.auth.signOut();
    if (error) {
      showMessage(mapErrorMessage(error), "err");
    } else {
      emailInput.value = "";
      passwordInput.value = "";
      showMessage("로그아웃되었습니다.", "ok");
    }
  } catch (error) {
    showMessage(mapErrorMessage(error), "err");
  } finally {
    setBusy(false);
  }
}

async function findLoginId() {
  if (!supabase) return;

  const fullName = idFindNameInput.value.trim();
  const phone = normalizePhone(idFindPhoneInput.value);
  const birthDate = idFindBirthInput.value;

  if (!fullName || !phone || !birthDate) {
    showInlineMessage(idFindResult, "이름, 전화번호, 생년월일을 모두 입력해 주세요.", "err");
    return;
  }

  if (phone.length < 10 || phone.length > 11) {
    showInlineMessage(idFindResult, "전화번호는 숫자 10~11자리로 입력해 주세요.", "err");
    return;
  }

  await runWithButtonBusy(idFindBtn, "조회 중...", async () => {
    const { data, error } = await supabase.rpc("find_login_id_masked", {
      p_full_name: fullName,
      p_phone: phone,
      p_birth_date: birthDate
    });

    if (error) {
      showInlineMessage(idFindResult, mapErrorMessage(error), "err");
      return;
    }

    if (!data) {
      showInlineMessage(idFindResult, "일치하는 계정을 찾지 못했습니다.", "err");
      return;
    }

    showInlineMessage(idFindResult, `가입된 ID: ${data}`, "ok");
  });
}

async function sendPasswordReset() {
  if (!supabase) return;

  const loginId = normalizeLoginId(pwFindLoginIdInput.value);
  const phone = normalizePhone(pwFindPhoneInput.value);
  const birthDate = pwFindBirthInput.value;
  const email = pwFindEmailInput.value.trim().toLowerCase();

  if (!loginId || !phone || !birthDate || !email) {
    showInlineMessage(pwFindResult, "로그인 ID, 전화번호, 생년월일, 이메일을 모두 입력해 주세요.", "err");
    return;
  }

  if (!isValidLoginId(loginId)) {
    showInlineMessage(pwFindResult, "로그인 ID 형식이 올바르지 않습니다.", "err");
    return;
  }

  if (phone.length < 10 || phone.length > 11) {
    showInlineMessage(pwFindResult, "전화번호는 숫자 10~11자리로 입력해 주세요.", "err");
    return;
  }

  await runWithButtonBusy(pwFindBtn, "전송 중...", async () => {
    const { data: maskedEmail, error: maskedError } = await supabase.rpc(
      "find_email_masked_for_password_reset",
      {
        p_login_id: loginId,
        p_phone: phone,
        p_birth_date: birthDate
      }
    );

    if (maskedError) {
      showInlineMessage(pwFindResult, mapErrorMessage(maskedError), "err");
      return;
    }

    if (!maskedEmail) {
      showInlineMessage(pwFindResult, "입력하신 정보와 일치하는 계정을 찾지 못했습니다.", "err");
      return;
    }

    const { data: verifyMatch, error: verifyError } = await supabase.rpc(
      "verify_password_reset_identity",
      {
        p_login_id: loginId,
        p_email: email,
        p_phone: phone,
        p_birth_date: birthDate
      }
    );

    if (verifyError) {
      showInlineMessage(pwFindResult, mapErrorMessage(verifyError), "err");
      return;
    }

    if (!verifyMatch) {
      showInlineMessage(
        pwFindResult,
        `계정은 확인됐지만 이메일이 다릅니다. 등록된 이메일 힌트: ${maskedEmail}`,
        "err"
      );
      return;
    }

    const redirectTo = `${window.location.origin}/`;
    const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo
    });

    if (resetError) {
      showInlineMessage(
        pwFindResult,
        `${mapErrorMessage(resetError)} (Supabase Auth > URL Configuration에 ${redirectTo} 등록 필요)`,
        "err"
      );
      return;
    }

    showInlineMessage(
      pwFindResult,
      `비밀번호 재설정 메일을 보냈습니다. (${maskedEmail})`,
      "ok"
    );
  });
}

function bindClick(el, handler) {
  if (el) {
    el.addEventListener("click", handler);
  }
}

bindClick(loginBtn, signIn);
bindClick(signupBtn, signUp);
bindClick(logoutBtn, signOut);
bindClick(cancelSignupBtn, () => {
  setSignupMode(false);
  clearSignupExtraFields();
  showMessage("로그인 모드로 돌아왔습니다.", "");
});
bindClick(openIdFindBtn, () => togglePanel(idFindPanel));
bindClick(openPwFindBtn, () => togglePanel(pwFindPanel));
bindClick(idFindBtn, findLoginId);
bindClick(pwFindBtn, sendPasswordReset);

if (supabase) {
  supabase.auth.onAuthStateChange((_event, session) => renderSession(session));
}

setSignupMode(false);
syncEnabledState();
initializeSession();
