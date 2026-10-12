function loginFailureMessage(status, error) {
  if (status === 401 || error === 'AUTHENTICATION_FAILED') {
    return '이메일 또는 비밀번호를 확인해 주세요.';
  }
  if (status === 429) return '로그인 시도가 많습니다. 잠시 후 다시 시도해 주세요.';
  return '로그인할 수 없습니다. 연결과 계정 설정을 확인한 뒤 다시 시도해 주세요.';
}

function validUserPayload(value) {
  return value?.authenticated === true
    && typeof value.user?.id === 'string'
    && (value.user.email === null || typeof value.user.email === 'string');
}

export function createAuthController(onStateChange = () => {}, fetchImpl = globalThis.fetch) {
  if (typeof onStateChange !== 'function' || typeof fetchImpl !== 'function') {
    throw new TypeError('invalid_auth_controller_configuration');
  }

  let state = {
    authenticated: false,
    email: null,
    loading: true,
    busy: false,
    message: '',
    messageType: 'status',
    sessionRevision: 0,
  };
  let activeUserId = null;
  let csrfToken = null;
  let refreshInFlight = null;

  function update(patch) {
    state = { ...state, ...patch };
    onStateChange({ ...state });
  }

  function setAuthenticated(user, message = '') {
    if (!state.authenticated || activeUserId !== user.id) {
      state = { ...state, sessionRevision: state.sessionRevision + 1 };
    }
    activeUserId = user.id;
    update({
      authenticated: true,
      email: user.email,
      loading: false,
      message,
      messageType: 'status',
    });
  }

  function clearSession(message = '', messageType = 'status') {
    if (state.authenticated || activeUserId !== null) {
      state = { ...state, sessionRevision: state.sessionRevision + 1 };
    }
    activeUserId = null;
    csrfToken = null;
    update({
      authenticated: false,
      email: null,
      loading: false,
      message,
      messageType,
    });
  }

  async function readResponse(response) {
    let body;
    try {
      body = await response.json();
    } catch {
      throw new Error('INVALID_API_RESPONSE');
    }
    return body;
  }

  async function fetchCsrfToken() {
    const response = await fetchImpl('/api/auth/csrf', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
    });
    const body = await readResponse(response);
    if (!response.ok || typeof body?.csrfToken !== 'string' || !body.csrfToken) {
      throw new Error('CSRF_TOKEN_UNAVAILABLE');
    }
    csrfToken = body.csrfToken;
    return csrfToken;
  }

  async function sendCsrfPost(path, body) {
    const token = await fetchCsrfToken();
    return fetchImpl(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }

  async function refreshSession(expiredMessage = '세션이 만료되었습니다. 다시 로그인해 주세요.') {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      try {
        const response = await sendCsrfPost('/api/auth/refresh', {});
        const body = await readResponse(response);
        if (!response.ok || !validUserPayload(body)) {
          clearSession(expiredMessage);
          return false;
        }
        setAuthenticated(body.user);
        return true;
      } catch {
        clearSession(expiredMessage, 'error');
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
    return refreshInFlight;
  }

  async function initialize() {
    try {
      const response = await fetchImpl('/api/auth/session', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
      });
      const body = await readResponse(response);
      if (response.ok && validUserPayload(body)) {
        setAuthenticated(body.user);
        return;
      }
      if (response.status === 401) {
        await refreshSession('기존 브라우저 로그인은 자동 이전되지 않습니다. 이메일과 비밀번호로 다시 로그인해 주세요.');
        return;
      }
      clearSession('로그인 상태를 확인할 수 없습니다. 페이지를 새로고침해 주세요.', 'error');
    } catch {
      clearSession('로그인 상태를 확인할 수 없습니다. 연결을 확인해 주세요.', 'error');
    }
  }

  async function signIn(email, password) {
    if (state.loading || state.busy) return false;
    if (typeof email !== 'string' || !email.trim()
        || typeof password !== 'string' || !password) {
      update({ message: '이메일과 비밀번호를 입력해 주세요.', messageType: 'error' });
      return false;
    }

    update({ busy: true, message: '', messageType: 'status' });
    try {
      const response = await sendCsrfPost('/api/auth/login', {
        email: email.trim(),
        password,
      });
      const body = await readResponse(response);
      if (!response.ok || !validUserPayload(body)) {
        update({
          message: loginFailureMessage(response.status, body?.error),
          messageType: 'error',
        });
        return false;
      }
      setAuthenticated(body.user, '로그인되었습니다.');
      return true;
    } catch {
      update({
        message: '로그인할 수 없습니다. 연결 상태를 확인한 뒤 다시 시도해 주세요.',
        messageType: 'error',
      });
      return false;
    } finally {
      update({ busy: false });
    }
  }

  async function signOut() {
    if (state.loading || state.busy || !state.authenticated) return false;
    update({ busy: true, message: '', messageType: 'status' });
    try {
      const response = await sendCsrfPost('/api/auth/logout', {});
      const body = await readResponse(response);
      if (!response.ok || body?.authenticated !== false) {
        update({ message: '로그아웃하지 못했습니다. 다시 시도해 주세요.', messageType: 'error' });
        return false;
      }
      clearSession('로그아웃되었습니다.');
      return true;
    } catch {
      update({ message: '로그아웃하지 못했습니다. 다시 시도해 주세요.', messageType: 'error' });
      return false;
    } finally {
      update({ busy: false });
    }
  }

  async function request(path, options = {}) {
    if (!state.authenticated) throw new Error('AUTHENTICATION_REQUIRED');
    const method = (options.method ?? 'GET').toUpperCase();

    async function send() {
      const headers = new Headers(options.headers);
      if (['POST', 'PUT', 'DELETE'].includes(method)) {
        headers.set('X-CSRF-Token', await fetchCsrfToken());
      }
      return fetchImpl(path, {
        ...options,
        method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers,
      });
    }

    let response = await send();
    if (response.status === 401) {
      if (!await refreshSession()) throw new Error('AUTH_SESSION_EXPIRED');
      response = await send();
      if (response.status === 401) {
        clearSession('세션이 만료되었습니다. 다시 로그인해 주세요.');
        throw new Error('AUTH_SESSION_EXPIRED');
      }
    }

    const body = await readResponse(response);
    if (!response.ok) {
      throw new Error(typeof body?.error === 'string' ? body.error : 'API_REQUEST_FAILED');
    }
    return body;
  }

  async function expireSession() {
    clearSession('세션이 만료되었습니다. 다시 로그인해 주세요.');
    return true;
  }

  return {
    get state() { return { ...state }; },
    initialize,
    signIn,
    signOut,
    request,
    expireSession,
  };
}
