function loginFailureMessage(error) {
  if (error?.code === 'email_not_confirmed') {
    return '로그인 전에 이메일 주소 확인을 완료해 주세요.';
  }
  if (error?.code === 'invalid_credentials' || error?.code === 'invalid_grant'
      || error?.status === 400) {
    return '이메일 또는 비밀번호를 확인해 주세요.';
  }
  if (error?.status === 429) return '로그인 시도가 많습니다. 잠시 후 다시 시도해 주세요.';
  return '로그인할 수 없습니다. 연결과 계정 설정을 확인한 뒤 다시 시도해 주세요.';
}

export function createAuthorizationHeader(accessToken) {
  if (typeof accessToken !== 'string' || !accessToken) {
    throw new TypeError('invalid_access_token');
  }
  return `Bearer ${accessToken}`;
}

export function createAuthController(supabase, onStateChange = () => {}) {
  const auth = supabase?.auth;
  if (!auth || typeof onStateChange !== 'function') {
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
  let authEventRevision = 0;
  let activeAccessToken = null;

  function update(patch) {
    state = { ...state, ...patch };
    onStateChange({ ...state });
  }

  function setSession(session, message = '') {
    const accessToken = typeof session?.access_token === 'string' && session.access_token
      ? session.access_token
      : null;
    if (accessToken !== activeAccessToken) {
      activeAccessToken = accessToken;
      state = { ...state, sessionRevision: state.sessionRevision + 1 };
    }
    update({
      authenticated: Boolean(session?.user && accessToken),
      email: typeof session?.user?.email === 'string' ? session.user.email : null,
      loading: false,
      message,
      messageType: message ? 'status' : 'status',
    });
  }

  const subscriptionResult = auth.onAuthStateChange((event, session) => {
    authEventRevision += 1;
    const message = event === 'SIGNED_IN' ? '로그인되었습니다.'
      : event === 'SIGNED_OUT' ? '로그아웃되었습니다.' : '';
    setSession(session, message);
  });

  async function initialize() {
    const startRevision = authEventRevision;
    try {
      const { data, error } = await auth.getSession();
      if (startRevision !== authEventRevision) return;
      if (error) throw new Error('session_unavailable');
      setSession(data?.session ?? null);
    } catch {
      if (startRevision === authEventRevision) {
        update({ loading: false, message: '로그인 상태를 확인할 수 없습니다. 페이지를 새로고침해 주세요.', messageType: 'error' });
      }
    }
  }

  async function signIn(email, password) {
    if (state.loading || state.busy) return false;
    if (typeof email !== 'string' || !email.trim() || typeof password !== 'string' || !password) {
      update({ message: '이메일과 비밀번호를 입력해 주세요.', messageType: 'error' });
      return false;
    }

    update({ busy: true, message: '', messageType: 'status' });
    try {
      const { data, error } = await auth.signInWithPassword({ email: email.trim(), password });
      if (error) {
        update({ message: loginFailureMessage(error), messageType: 'error' });
        return false;
      }
      if (!data?.session) {
        update({ message: '로그인 세션을 만들지 못했습니다. 다시 시도해 주세요.', messageType: 'error' });
        return false;
      }
      setSession(data.session, '로그인되었습니다.');
      return true;
    } catch {
      update({ message: '로그인할 수 없습니다. 연결 상태를 확인한 뒤 다시 시도해 주세요.', messageType: 'error' });
      return false;
    } finally {
      update({ busy: false });
    }
  }

  async function signOut() {
    if (state.loading || state.busy || !state.authenticated) return false;
    update({ busy: true, message: '', messageType: 'status' });
    try {
      const { error } = await auth.signOut();
      if (error) {
        update({ message: '로그아웃하지 못했습니다. 다시 시도해 주세요.', messageType: 'error' });
        return false;
      }
      setSession(null, '로그아웃되었습니다.');
      return true;
    } catch {
      update({ message: '로그아웃하지 못했습니다. 다시 시도해 주세요.', messageType: 'error' });
      return false;
    } finally {
      update({ busy: false });
    }
  }

  async function getAccessToken() {
    try {
      const { data, error } = await auth.getSession();
      if (error) throw new Error('session_unavailable');
      return state.authenticated && typeof data?.session?.access_token === 'string'
        ? data.session.access_token
        : null;
    } catch {
      throw new Error('AUTH_SESSION_UNAVAILABLE');
    }
  }

  async function expireSession() {
    authEventRevision += 1;
    try {
      const { error } = await auth.signOut({ scope: 'local' });
      if (error) throw new Error('session_cleanup_failed');
    } catch {
      setSession(null, '서버 인증이 만료되었습니다. 다시 로그인해 주세요.');
      return false;
    }
    setSession(null, '서버 인증이 만료되었습니다. 다시 로그인해 주세요.');
    return true;
  }

  return {
    get state() { return { ...state }; },
    initialize,
    signIn,
    signOut,
    getAccessToken,
    expireSession,
    dispose() { subscriptionResult?.data?.subscription?.unsubscribe(); },
  };
}