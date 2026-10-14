import { createAuthController } from './auth-controller.mjs';

const form = document.querySelector('#login-form');
const emailInput = document.querySelector('#login-email');
const passwordInput = document.querySelector('#login-password');
const loginButton = document.querySelector('#login-button');
const loginPanel = document.querySelector('#login-panel');
const accountPanel = document.querySelector('#account-panel');
const accountEmail = document.querySelector('#account-email');
const logoutButton = document.querySelector('#logout-button');
const authStatus = document.querySelector('#auth-status');
const notesList = document.querySelector('#notes');
const notesStatus = document.querySelector('#notes-status');
const reloadNotesButton = document.querySelector('#reload-notes');
const newNoteButton = document.querySelector('#new-note');
const noteForm = document.querySelector('#note-form');
const noteFormHeading = document.querySelector('#note-form-heading');
const noteTitle = document.querySelector('#note-title');
const noteBody = document.querySelector('#note-body');
const saveNoteButton = document.querySelector('#save-note');
const deleteNoteButton = document.querySelector('#delete-note');
const cancelEditButton = document.querySelector('#cancel-edit');
const installButton = document.querySelector('#install-button');
const installStatus = document.querySelector('#install-status');
const offlineRefreshButton = document.querySelector('#offline-refresh');
const deviceStatusBadge = document.querySelector('#device-status');
const deviceMessage = document.querySelector('#device-message');
const deviceRequestButton = document.querySelector('#device-request-button');
const deviceRevokeButton = document.querySelector('#device-revoke-button');
const operationPanel = document.querySelector('#operation-panel');
const operationMessage = document.querySelector('#operation-message');
const operationSummary = document.querySelector('#operation-summary');
const operationRefresh = document.querySelector('#operation-refresh');
const verificationCounts = document.querySelector('#verification-counts');
const verificationRows = document.querySelector('#verification-rows');

let controller = null;
let previousAuthenticated = false;
let previousSessionRevision = 0;
let notesRequestId = 0;
let selectedNoteId = null;
let requestInFlight = false;
let deferredInstallPrompt = null;
let installPromptSeen = false;
let deviceState = { status: 'unregistered', approved: false, pending: false };

function renderOperationReport(report) {
  if (report?.schema !== 'aleph.operations.v1' || !Array.isArray(report.verification?.cases)) {
    throw new Error('INVALID_OPERATION_REPORT');
  }
  const cases = report.verification.cases;
  if (!Array.isArray(report.policy?.ruleIds)
      || report.policy.count !== report.policy.ruleIds.length) {
    throw new Error('INVALID_OPERATION_RULE_COUNT');
  }
  const pass = cases.filter(item => item.status === 'PASS').length;
  const fail = cases.filter(item => item.status === 'FAIL').length;
  const notRun = cases.filter(item => item.status === 'NOT_RUN').length;
  if (cases.length !== 41) throw new Error('INVALID_OPERATION_CASES');
  if (report.verification.counts?.pass !== pass || report.verification.counts?.fail !== fail
      || report.verification.counts?.notRun !== notRun) throw new Error('INVALID_OPERATION_COUNTS');
  operationSummary.replaceChildren();
  const summary = [
    ['판정기 규칙', `${report.policy?.ruleIds?.join(', ') || '확인 불가'} · 운영 판정 ${report.policy?.status || 'UNKNOWN'}`],
    ['탐지 사건', report.detection?.status || 'UNKNOWN'],
    ['접속 회수', report.revocation?.status || 'UNKNOWN'],
    ['복구 버전', `${report.recovery?.version || '확인 불가'} · ${report.recovery?.status || 'UNKNOWN'} (${report.recovery?.source || '출처 없음'})`],
    ['현재 기기 승인', report.deviceApproval?.status || 'unknown'],
  ];
  for (const [label, value] of summary) {
    const item = document.createElement('li');
    const heading = document.createElement('strong');
    const detail = document.createElement('span');
    heading.textContent = label;
    detail.textContent = value;
    item.append(heading, detail);
    operationSummary.append(item);
  }
  verificationCounts.textContent = `실측 PASS ${pass} · FAIL ${fail} · NOT_RUN ${notRun} · 배포 기준 커밋 ${report.checkedCommit || '확인 불가'}`;
  verificationRows.replaceChildren();
  for (const item of cases) {
    const row = document.createElement('tr');
    const values = [
      `${item.name} / ${item.request ?? '요청 미기록'}`,
      item.expected,
      item.actual ? `HTTP ${item.actual.httpStatus ?? '응답 없음'} · ${item.actual.body ?? 'response body redacted'}` : '미실행',
      item.requestId ? `${item.requestId} (작전실 상관 ID) / ${item.checkedAt}` : '미실행',
      item.status,
    ];
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    verificationRows.append(row);
  }
  operationMessage.textContent = '서버에서 검증 기록과 현재 기기 상태를 확인했습니다. 운영 엔진 상태는 별도로 표시합니다.';
}

async function loadOperationReport() {
  if (!controller?.state.authenticated) return;
  if (!deviceState.approved) {
    operationMessage.textContent = '기기 승인 후 작전실 기록을 확인할 수 있습니다.';
    return;
  }
  const revision = controller.state.sessionRevision;
  operationMessage.textContent = '검증 기록을 불러오는 중입니다.';
  try {
    const report = await controller.request('/api/operations', { method: 'GET' });
    if (controller.state.authenticated && controller.state.sessionRevision === revision) {
      renderOperationReport(report);
    }
  } catch {
    if (controller.state.authenticated && controller.state.sessionRevision === revision) {
      operationSummary.replaceChildren();
      verificationRows.replaceChildren();
      verificationCounts.textContent = '';
      operationMessage.textContent = '서버 기록을 확인할 수 없습니다. 상태는 확인 불가입니다.';
    }
  }
}

function clearEditor() {
  selectedNoteId = null;
  noteForm.reset();
  noteForm.hidden = true;
  deleteNoteButton.hidden = true;
  deleteNoteButton.disabled = true;
  noteFormHeading.textContent = '새 메모';
  saveNoteButton.textContent = '저장';
}

function clearNotes() {
  notesRequestId += 1;
  notesList.replaceChildren();
  clearEditor();
  notesStatus.textContent = '로그인하면 메모를 불러옵니다.';
  notesStatus.dataset.kind = 'status';
}

function setBusy(busy) {
  requestInFlight = busy;
  const unauthenticated = !controller?.state.authenticated;
  const notesDisabled = busy || unauthenticated || !deviceState.approved;
  logoutButton.disabled = unauthenticated || controller?.state.loading || controller?.state.busy;
  reloadNotesButton.disabled = notesDisabled;
  newNoteButton.disabled = notesDisabled;
  saveNoteButton.disabled = notesDisabled;
  deleteNoteButton.disabled = notesDisabled || !selectedNoteId;
  cancelEditButton.disabled = notesDisabled;
  deviceRequestButton.disabled = busy || unauthenticated;
  deviceRevokeButton.disabled = busy || unauthenticated || !deviceState.approved;
  for (const button of notesList.querySelectorAll('button')) button.disabled = notesDisabled;
}

function render(state) {
  loginPanel.hidden = state.authenticated;
  accountPanel.hidden = !state.authenticated;
  accountEmail.textContent = state.email ? `로그인 계정: ${state.email}` : '로그인되었습니다.';
  authStatus.textContent = state.message || (state.loading ? '로그인 상태를 확인하는 중입니다.' : '');
  authStatus.dataset.kind = state.messageType;

  const disabled = state.loading || state.busy;
  loginButton.disabled = disabled;
  emailInput.disabled = disabled;
  passwordInput.disabled = disabled;
  loginButton.textContent = state.busy ? '처리 중...' : '로그인';
  logoutButton.disabled = disabled;

  if (state.authenticated && state.sessionRevision !== previousSessionRevision && controller) {
    clearEditor();
    void initializeDeviceSession();
  }
  if (!state.authenticated && previousAuthenticated) clearNotes();
  if (!state.authenticated) {
    operationSummary.replaceChildren();
    verificationRows.replaceChildren();
    verificationCounts.textContent = '';
    operationMessage.textContent = '로그인 후 검증 기록을 확인합니다.';
    deviceState = { status: 'unregistered', approved: false, pending: false };
    deviceStatusBadge.dataset.state = 'unregistered';
    deviceStatusBadge.textContent = '미등록';
    deviceMessage.textContent = '로그인 후 기기 승인 상태를 확인합니다.';
    deviceRequestButton.disabled = true;
    deviceRevokeButton.hidden = true;
    clearNotes();
  }
  previousAuthenticated = state.authenticated;
  operationPanel.hidden = !state.authenticated;
  previousSessionRevision = state.sessionRevision;
  setBusy(requestInFlight);
}

function updateDeviceBadge(status, message) {
  const statuses = new Set(['unregistered', 'pending', 'approved', 'rejected', 'revoked', 'expired', 'unknown']);
  const nextStatus = statuses.has(status) ? status : 'unknown';
  deviceState = {
    status: nextStatus,
    approved: nextStatus === 'approved',
    pending: nextStatus === 'pending',
  };
  deviceStatusBadge.dataset.state = nextStatus;
  deviceStatusBadge.textContent = nextStatus === 'approved' ? '승인됨' : nextStatus === 'pending' ? '승인 대기' : nextStatus === 'revoked' ? '승인 취소' : nextStatus === 'rejected' ? '거절됨' : nextStatus === 'expired' ? '승인 만료' : nextStatus === 'unknown' ? '확인 불가' : '미등록';
  deviceRevokeButton.hidden = nextStatus !== 'approved';
  deviceMessage.textContent = message || '기기 승인 상태를 확인하고 있습니다.';
  if (nextStatus !== 'approved') clearNotes();
  setBusy(requestInFlight);
}

async function refreshDeviceStatus() {
  if (!controller?.state.authenticated) {
    updateDeviceBadge('unregistered', '로그인 후 기기 승인 상태를 확인합니다.');
    return false;
  }
  try {
    const result = await controller.request('/api/device', { method: 'GET', cache: 'no-store' });
    if (typeof result?.status === 'string'
        && typeof result.approved === 'boolean'
        && result.approved === (result.status === 'approved')) {
      updateDeviceBadge(result.status, result.approved ? '서버에서 승인된 기기입니다.' : result.pending ? '승인 요청이 접수되었습니다. 서버 검증을 기다려 주세요.' : '기기 승인 전에는 보호 자료에 접근할 수 없습니다.');
      return result.approved;
    }
  } catch {
    updateDeviceBadge('unknown', '기기 승인 상태를 확인할 수 없습니다. 잠시 후 다시 시도해 주세요.');
    return false;
  }
  updateDeviceBadge('unknown', '기기 승인 상태를 확인할 수 없습니다.');
  return false;
}

async function initializeDeviceSession() {
  const wasApproved = deviceState.approved;
  if (await refreshDeviceStatus()) {
    if (!wasApproved) await loadNotes();
    await loadOperationReport();
  } else {
    notesList.replaceChildren();
    clearEditor();
    notesStatus.textContent = '이 기기는 승인 전이므로 보호 메모에 접근할 수 없습니다.';
    notesStatus.dataset.kind = 'status';
  }
}

async function requestDeviceApproval() {
  if (!controller?.state.authenticated) return;
  try {
    deviceRequestButton.disabled = true;
    const result = await controller.request('/api/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'request' }),
    });
    if (result?.status === 'pending') {
      updateDeviceBadge('pending', '승인 요청을 접수했습니다. 서버에서 승인 여부를 확인할 수 있습니다.');
      notesStatus.textContent = '승인 대기 중입니다. 보호 메모는 계속 차단됩니다.';
      return;
    }
    if (result?.status === 'approved') {
      updateDeviceBadge('approved', '서버가 이 기기를 승인했습니다. 보호 자료를 다시 확인할 수 있습니다.');
      await loadNotes();
      return;
    }
    updateDeviceBadge('unknown', '기기 승인 요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.');
  } catch {
    updateDeviceBadge('unknown', '기기 승인 요청 중 문제가 발생했습니다. 잠시 후 다시 시도해 주세요.');
  }
}

async function revokeDeviceApproval() {
  if (!controller?.state.authenticated || !deviceState.approved) return;
  try {
    const result = await controller.request('/api/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'revoke' }),
    });
    updateDeviceBadge(result?.status === 'revoked' ? 'revoked' : 'unknown',
      result?.status === 'revoked' ? '이 기기의 승인이 취소되었습니다.' : '승인 취소 상태를 확인할 수 없습니다.');
  } catch {
    updateDeviceBadge('unknown', '승인을 취소하지 못했습니다. 서버에서 현재 상태를 확인해 주세요.');
  }
}

async function apiRequest(path, options = {}) {
  if (requestInFlight) throw new Error('REQUEST_IN_PROGRESS');
  setBusy(true);
  try {
    const sessionRevision = controller.state.sessionRevision;
    const result = await controller.request(path, options);
    if (!controller.state.authenticated || sessionRevision !== controller.state.sessionRevision) {
      throw new Error('AUTH_SESSION_CHANGED');
    }
    return result;
  } finally {
    setBusy(false);
  }
}

function renderNotes(notes) {
  notesList.replaceChildren(...notes.map(note => {
    const item = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.noteId = note.id;
    button.textContent = note.title;
    item.append(button);
    return item;
  }));
}

async function loadNotes() {
  const requestId = ++notesRequestId;
  if (!controller?.state.authenticated || !deviceState.approved) {
    notesList.replaceChildren();
    clearEditor();
    notesStatus.textContent = '이 기기는 승인 전이므로 보호 메모에 접근할 수 없습니다.';
    notesStatus.dataset.kind = 'status';
    return;
  }
  notesStatus.textContent = '메모를 불러오는 중입니다.';
  notesStatus.dataset.kind = 'status';
  notesList.replaceChildren();
  try {
    const result = await apiRequest('/api/notes');
    if (!Array.isArray(result.notes) || result.notes.some(note =>
      typeof note.id !== 'string' || typeof note.title !== 'string' || typeof note.body !== 'string')) {
      throw new Error('INVALID_NOTES');
    }
    if (requestId !== notesRequestId || !controller.state.authenticated) return;
    renderNotes(result.notes);
    notesStatus.textContent = `${result.notes.length}개 메모를 불러왔습니다.`;
  } catch (error) {
    if (requestId !== notesRequestId || !controller.state.authenticated) return;
    if (['DEVICE_NOT_APPROVED', 'DEVICE_STATUS_UNAVAILABLE'].includes(error.message)) {
      updateDeviceBadge('unknown', '서버에서 기기 승인을 확인하지 못해 메모 접근을 차단했습니다.');
      notesList.replaceChildren();
      clearEditor();
      return;
    }
    notesStatus.textContent = error.message === 'REQUEST_IN_PROGRESS'
      ? '요청을 처리 중입니다.'
      : '메모를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.';
    notesStatus.dataset.kind = 'error';
  }
}

function openCreateForm() {
  clearEditor();
  noteForm.hidden = false;
  noteTitle.focus();
}

async function openNote(id) {
  const requestId = notesRequestId;
  const sessionRevision = controller.state.sessionRevision;
  notesStatus.textContent = '메모를 불러오는 중입니다.';
  notesStatus.dataset.kind = 'status';
  try {
    const note = await apiRequest(`/api/notes/${encodeURIComponent(id)}`);
    if (requestId !== notesRequestId || sessionRevision !== controller.state.sessionRevision
        || !deviceState.approved) return;
    if (typeof note.id !== 'string' || typeof note.title !== 'string' || typeof note.body !== 'string') {
      throw new Error('INVALID_NOTE');
    }
    selectedNoteId = note.id;
    noteTitle.value = note.title;
    noteBody.value = note.body;
    noteFormHeading.textContent = '메모 수정';
    saveNoteButton.textContent = '수정 저장';
    deleteNoteButton.hidden = false;
    noteForm.hidden = false;
    setBusy(requestInFlight);
    notesStatus.textContent = '메모 내용을 불러왔습니다.';
    noteTitle.focus();
  } catch {
    if (controller.state.authenticated) {
      notesStatus.textContent = '메모를 열지 못했습니다. 목록을 새로고침해 주세요.';
      notesStatus.dataset.kind = 'error';
    }
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!controller) return;
  const succeeded = await controller.signIn(emailInput.value, passwordInput.value);
  passwordInput.value = '';
  if (!succeeded) passwordInput.focus();
});

logoutButton.addEventListener('click', () => {
  if (controller) void controller.signOut();
});

reloadNotesButton.addEventListener('click', () => {
  if (controller?.state.authenticated) {
    void (async () => {
      if (await refreshDeviceStatus()) await loadNotes();
    })();
  }
});

newNoteButton.addEventListener('click', openCreateForm);
cancelEditButton.addEventListener('click', clearEditor);

notesList.addEventListener('click', event => {
  const button = event.target.closest('button[data-note-id]');
  if (button && controller?.state.authenticated && deviceState.approved) void openNote(button.dataset.noteId);
});

noteForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!controller?.state.authenticated || requestInFlight) return;
  const editingId = selectedNoteId;
  notesStatus.textContent = editingId ? '메모를 수정하는 중입니다.' : '메모를 저장하는 중입니다.';
  notesStatus.dataset.kind = 'status';
  try {
    const result = await apiRequest(
      editingId ? `/api/notes/${encodeURIComponent(editingId)}` : '/api/notes',
      {
        method: editingId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: noteTitle.value, body: noteBody.value }),
      },
    );
    if (!controller.state.authenticated) return;
    clearEditor();
    await loadNotes();
    notesStatus.textContent = editingId
      ? '메모를 수정했습니다.'
      : `메모를 추가했습니다. (${result.id})`;
  } catch {
    if (controller.state.authenticated) {
      notesStatus.textContent = '메모를 저장하지 못했습니다. 입력 내용과 연결을 확인해 주세요.';
      notesStatus.dataset.kind = 'error';
    }
  }
});

deleteNoteButton.addEventListener('click', async () => {
  if (!selectedNoteId || !controller?.state.authenticated || requestInFlight) return;
  if (!window.confirm('이 메모를 삭제할까요?')) return;
  notesStatus.textContent = '메모를 삭제하는 중입니다.';
  notesStatus.dataset.kind = 'status';
  try {
    await apiRequest(`/api/notes/${encodeURIComponent(selectedNoteId)}`, { method: 'DELETE' });
    if (!controller.state.authenticated) return;
    clearEditor();
    await loadNotes();
    notesStatus.textContent = '메모를 삭제했습니다.';
  } catch {
    if (controller.state.authenticated) {
      notesStatus.textContent = '메모를 삭제하지 못했습니다. 목록을 새로고침해 주세요.';
      notesStatus.dataset.kind = 'error';
    }
  }
});

deviceRevokeButton.addEventListener('click', () => {
  void revokeDeviceApproval();
});

window.addEventListener('online', () => {
  if (controller?.state.authenticated) void initializeDeviceSession();
});

window.setInterval(() => {
  if (controller?.state.authenticated) void initializeDeviceSession();
}, 15000);

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      installStatus.textContent = '오프라인 앱 셸을 사용할 수 없습니다. 온라인 상태에서 새로고침해 주세요.';
    });
  });
}

window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  installPromptSeen = true;
  deferredInstallPrompt = event;
  installButton.hidden = false;
  installStatus.textContent = '이 브라우저는 앱 설치를 지원합니다. 설치 버튼을 눌러 홈 화면에 추가할 수 있습니다.';
});

window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  installButton.hidden = true;
  installStatus.textContent = '앱이 설치되었습니다. 서버에서 기기 승인 상태와 로그인 상태를 별도로 확인합니다.';
});

const installedApp = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
if (installedApp) {
  installButton.hidden = true;
  installStatus.textContent = '설치된 앱 모드입니다. 보호 자료는 서버 승인 상태를 별도로 확인합니다.';
} else {
  window.addEventListener('load', () => {
    window.setTimeout(() => {
      if (installPromptSeen || installedApp) return;
      installButton.hidden = true;
      installStatus.textContent = /iPad|iPhone|iPod/u.test(navigator.userAgent)
        ? '설치 메뉴가 보이지 않으면 Safari 공유 메뉴에서 "홈 화면에 추가"를 선택하세요. 설치해도 기기 승인은 별도로 필요합니다.'
        : '이 브라우저는 설치 안내를 제공하지 않습니다. 최신 브라우저에서 이용하거나 오프라인 안내를 확인하세요.';
    }, 1200);
  });
}

installButton.addEventListener('click', async () => {
  if (!deferredInstallPrompt) {
    installStatus.textContent = '설치 지원이 없거나 이미 설치된 상태입니다.';
    return;
  }
  deferredInstallPrompt.prompt();
  try {
    const choice = await deferredInstallPrompt.userChoice;
    installStatus.textContent = choice?.outcome === 'accepted'
      ? '앱 설치를 요청했습니다. 서버 기기 승인은 별도로 확인해야 합니다.'
      : '앱 설치가 취소되었습니다. 로그인과 기기 승인 상태는 변경되지 않았습니다.';
  } catch {
    installStatus.textContent = '앱 설치 요청을 완료하지 못했습니다. 브라우저 설치 메뉴를 확인해 주세요.';
  }
  deferredInstallPrompt = null;
  installButton.hidden = true;
});

offlineRefreshButton.addEventListener('click', () => {
  if (navigator.onLine) {
    installStatus.textContent = '네트워크가 연결되어 있습니다. 최신 인증 상태를 서버에서 다시 확인합니다.';
    return;
  }
  installStatus.textContent = '오프라인 상태입니다. 보호 자료는 서버에서 다시 검증되고 캐시에는 민감 정보가 저장되지 않습니다.';
});

deviceRequestButton.addEventListener('click', () => {
  void requestDeviceApproval();
});

operationRefresh.addEventListener('click', () => { void loadOperationReport(); });

controller = createAuthController(render);
render(controller.state);
void controller.initialize();
