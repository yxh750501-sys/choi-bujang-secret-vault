import { createAuthController, createAuthorizationHeader } from './auth-controller.mjs';

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

let controller = null;
let previousAuthenticated = false;
let previousSessionRevision = 0;
let notesRequestId = 0;
let selectedNoteId = null;
let requestInFlight = false;

function clearEditor() {
  selectedNoteId = null;
  noteForm.reset();
  noteForm.hidden = true;
  deleteNoteButton.hidden = true;
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

function showSetupMessage() {
  loginButton.disabled = true;
  emailInput.disabled = true;
  passwordInput.disabled = true;
  authStatus.textContent = 'Supabase 로그인 설정이 아직 준비되지 않았습니다.';
  authStatus.dataset.kind = 'error';
}

function setBusy(busy) {
  requestInFlight = busy;
  const disabled = busy || !controller?.state.authenticated;
  logoutButton.disabled = disabled || controller?.state.busy;
  reloadNotesButton.disabled = disabled;
  newNoteButton.disabled = disabled;
  saveNoteButton.disabled = disabled;
  deleteNoteButton.disabled = disabled || !selectedNoteId;
  cancelEditButton.disabled = disabled;
  for (const button of notesList.querySelectorAll('button')) button.disabled = disabled;
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
    void loadNotes();
  }
  if (!state.authenticated && previousAuthenticated) clearNotes();
  previousAuthenticated = state.authenticated;
  previousSessionRevision = state.sessionRevision;
  setBusy(requestInFlight);
}

async function apiRequest(path, options = {}) {
  if (requestInFlight) throw new Error('REQUEST_IN_PROGRESS');
  setBusy(true);
  try {
    const sessionRevision = controller.state.sessionRevision;
    const accessToken = await controller.getAccessToken();
    if (!accessToken) {
      await controller.expireSession();
      throw new Error('AUTH_SESSION_EXPIRED');
    }
    const response = await fetch(path, {
      ...options,
      cache: 'no-store',
      headers: {
        ...options.headers,
        Authorization: createAuthorizationHeader(accessToken),
      },
    });
    if (!controller.state.authenticated || sessionRevision !== controller.state.sessionRevision) {
      throw new Error('AUTH_SESSION_CHANGED');
    }
    if (response.status === 401 || response.status === 403) {
      await controller.expireSession();
      throw new Error('AUTH_SESSION_EXPIRED');
    }
    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error('INVALID_API_RESPONSE');
    }
    if (!response.ok) throw new Error(typeof result?.error === 'string' ? result.error : 'API_REQUEST_FAILED');
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
  notesStatus.textContent = '메모를 불러오는 중입니다.';
  notesStatus.dataset.kind = 'status';
  try {
    const note = await apiRequest(`/api/notes/${encodeURIComponent(id)}`);
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
  if (controller?.state.authenticated) void loadNotes();
});

newNoteButton.addEventListener('click', openCreateForm);
cancelEditButton.addEventListener('click', clearEditor);

notesList.addEventListener('click', event => {
  const button = event.target.closest('button[data-note-id]');
  if (button && controller?.state.authenticated) void openNote(button.dataset.noteId);
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

const config = window.BYTE_BACK_SUPABASE_CONFIG;
if (!config?.supabaseUrl || !config?.publishableKey || !window.supabase?.createClient) {
  showSetupMessage();
  clearNotes();
} else {
  try {
    const supabase = window.supabase.createClient(config.supabaseUrl, config.publishableKey, {
      auth: { autoRefreshToken: true, persistSession: true, detectSessionInUrl: true },
    });
    controller = createAuthController(supabase, render);
    render(controller.state);
    void controller.initialize();
  } catch {
    showSetupMessage();
    clearNotes();
  }
}

export async function getAccessToken() {
  return controller ? controller.getAccessToken() : null;
}
