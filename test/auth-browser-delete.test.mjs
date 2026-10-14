import assert from 'node:assert/strict';
import { test } from 'node:test';

class FakeElement {
  constructor(tagName = 'div') {
    this.tagName = tagName.toUpperCase();
    this.hidden = false;
    this.disabled = false;
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
    this.value = '';
    this.textContent = '';
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  async dispatch(type, extra = {}) {
    const event = {
      preventDefault() {},
      target: this,
      ...extra,
    };
    for (const listener of this.listeners.get(type) ?? []) await listener(event);
  }

  append(...elements) {
    this.children.push(...elements);
  }

  replaceChildren(...elements) {
    this.children = elements;
  }

  querySelectorAll(selector) {
    if (selector !== 'button') return [];
    return this.children.flatMap(child => [
      ...(child.tagName === 'BUTTON' ? [child] : []),
      ...child.querySelectorAll(selector),
    ]);
  }

  closest(selector) {
    return selector === 'button[data-note-id]' && this.tagName === 'BUTTON'
      && typeof this.dataset.noteId === 'string'
      ? this
      : null;
  }

  reset() {}

  focus() {}
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

async function waitFor(predicate, message) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail(message);
}

test('saved note selection enables delete; successful and failed deletion preserve expected UI state', async () => {
  const ids = [
    '123e4567-e89b-42d3-a456-426614174101',
    '123e4567-e89b-42d3-a456-426614174102',
  ];
  const rows = new Map(ids.map((id, index) => [id, {
    id,
    title: `A note ${index + 1}`,
    body: `Fictional body ${index + 1}`,
  }]));
  const requests = [];
  let failNextDelete = false;
  let deleteStarted;
  let releaseDelete;
  const deleteGate = new Promise(resolve => {
    releaseDelete = resolve;
  });
  let holdNextDelete = false;
  let deleteCount = 0;
  const originalDocument = globalThis.document;
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const elements = new Map();
  const elementIds = [
    'login-form', 'login-email', 'login-password', 'login-button', 'login-panel',
    'account-panel', 'account-email', 'logout-button', 'auth-status', 'notes',
    'notes-status', 'reload-notes', 'new-note', 'note-form', 'note-form-heading',
    'note-title', 'note-body', 'save-note', 'delete-note', 'cancel-edit',
    'install-button', 'install-status', 'offline-refresh', 'device-status',
    'device-message', 'device-request-button', 'device-revoke-button',
    'operation-panel', 'operation-message', 'operation-summary',
    'operation-refresh', 'verification-counts', 'verification-rows',
  ];
  for (const id of elementIds) elements.set(`#${id}`, new FakeElement(id.includes('form') ? 'form' : 'div'));
  const noteForm = elements.get('#note-form');
  noteForm.reset = () => {
    elements.get('#note-title').value = '';
    elements.get('#note-body').value = '';
  };
  globalThis.document = {
    querySelector: selector => elements.get(selector),
    createElement: tagName => new FakeElement(tagName),
  };
  globalThis.window = {
    confirm: () => true,
    matchMedia: () => ({ matches: false }),
    addEventListener() {},
    setInterval() {},
  };
  globalThis.fetch = async (path, options = {}) => {
    requests.push({ path, options });
    assert.equal(options.credentials, 'same-origin');
    assert.equal(new Headers(options.headers).has('Authorization'), false);
    if (path === '/api/auth/session') {
      return jsonResponse({
        authenticated: true,
        user: { id: 'user-a', email: 'a@example.test' },
      });
    }
    if (path === '/api/auth/csrf') {
      return jsonResponse({ csrfToken: 'fake-csrf-ui-test-token' });
    }
    if (path === '/api/device') {
      return jsonResponse({ status: 'approved', approved: true, pending: false });
    }
    if (path === '/api/operations') {
      return jsonResponse({ schema: 'byteback.operation.v1', evidenceCommit: 'fixture',
        rules: { ids: [], status: 'NOT_RUN' }, detection: { status: 'NOT_RUN' },
        revocation: { status: 'UNKNOWN' }, recovery: { status: 'NOT_RUN' },
        deviceApproval: { status: 'approved' }, verification: {
          counts: { pass: 0, fail: 0, notRun: 0 }, cases: [],
        } });
    }
    if (path === '/api/notes' && (options.method ?? 'GET') === 'GET') {
      return jsonResponse({ notes: [...rows.values()] });
    }
    const itemPath = /^\/api\/notes\/([^/]+)$/u.exec(path);
    if (itemPath && (options.method ?? 'GET') === 'GET') {
      const row = rows.get(decodeURIComponent(itemPath[1]));
      return row ? jsonResponse(row) : jsonResponse({ error: 'NOTE_NOT_FOUND' }, 404);
    }
    if (itemPath && options.method === 'PUT') {
      assert.equal(new Headers(options.headers).get('x-csrf-token'), 'fake-csrf-ui-test-token');
      const row = rows.get(decodeURIComponent(itemPath[1]));
      if (!row) return jsonResponse({ error: 'NOTE_NOT_FOUND' }, 404);
      Object.assign(row, JSON.parse(options.body));
      return jsonResponse(row);
    }
    if (itemPath && options.method === 'DELETE') {
      deleteCount += 1;
      assert.equal(new Headers(options.headers).get('x-csrf-token'), 'fake-csrf-ui-test-token');
      assert.equal(options.body, undefined);
      if (holdNextDelete) {
        holdNextDelete = false;
        deleteStarted();
        await deleteGate;
      }
      if (failNextDelete) {
        failNextDelete = false;
        return jsonResponse({ error: 'NOTES_UNAVAILABLE' }, 503);
      }
      const id = decodeURIComponent(itemPath[1]);
      return rows.delete(id)
        ? jsonResponse({ id })
        : jsonResponse({ error: 'NOTE_NOT_FOUND' }, 404);
    }
    throw new Error(`Unexpected UI request: ${path}`);
  };

  try {
    await import(`../src/auth-browser.mjs?delete-ui-test=${Date.now()}`);
    const deleteButton = elements.get('#delete-note');
    const newButton = elements.get('#new-note');
    const notes = elements.get('#notes');
    const title = elements.get('#note-title');
    const body = elements.get('#note-body');
    const status = elements.get('#notes-status');

    await waitFor(() => notes.children.length === ids.length, 'initial note list did not load');
    await newButton.dispatch('click');
    assert.equal(deleteButton.disabled, true, 'new, unsaved note must not be deletable');
    await deleteButton.dispatch('click');
    assert.equal(deleteCount, 0, 'missing selected note ID must not send DELETE');

    await notes.dispatch('click', { target: notes.children[0].children[0] });
    await waitFor(() => !deleteButton.hidden, 'stored note editor did not open');
    assert.equal(title.value, 'A note 1');
    assert.equal(body.value, 'Fictional body 1');
    assert.equal(deleteButton.disabled, false, 'stored note selection enables delete');

    title.value = 'Updated A note';
    body.value = 'Updated fictional content';
    await elements.get('#note-form').dispatch('submit');
    await waitFor(() => notes.children.length === ids.length, 'updated note list did not reload');
    assert.equal(deleteButton.disabled, true, 'saved editor reset disables delete until a stored note is selected');

    await notes.dispatch('click', {
      target: notes.children.find(item => item.children[0].dataset.noteId === ids[0]).children[0],
    });
    await waitFor(() => !deleteButton.hidden && title.value === 'Updated A note',
      'reselected edited note editor did not open');
    assert.equal(deleteButton.disabled, false, 'reselected stored note enables delete');

    let signalDeleteStarted;
    const deleteIsPending = new Promise(resolve => {
      signalDeleteStarted = resolve;
    });
    deleteStarted = signalDeleteStarted;
    holdNextDelete = true;
    const countBeforeDelete = deleteCount;
    const deletion = deleteButton.dispatch('click');
    await deleteIsPending;
    assert.equal(deleteButton.disabled, true, 'delete is disabled while request is in progress');
    await deleteButton.dispatch('click');
    assert.equal(deleteCount, countBeforeDelete + 1, 'concurrent click must not send another DELETE');
    releaseDelete();
    await deletion;
    await waitFor(() => notes.children.length === ids.length - 1, 'deleted note list did not reload');
    assert.equal(deleteCount, countBeforeDelete + 1, 'successful UI action sends exactly one DELETE');
    assert.equal(elements.get('#note-form').hidden, true, 'successful deletion closes editor');
    assert.equal(title.value, '', 'successful deletion clears title');
    assert.equal(body.value, '', 'successful deletion clears body');
    assert.equal(deleteButton.disabled, true);

    await notes.dispatch('click', { target: notes.children[0].children[0] });
    await waitFor(() => !deleteButton.hidden, 'remaining stored note editor did not open');
    assert.equal(deleteButton.disabled, false);
    failNextDelete = true;
    const countBeforeFailure = deleteCount;
    await deleteButton.dispatch('click');
    assert.equal(deleteCount, countBeforeFailure + 1);
    assert.equal(notes.children.length, 1, 'failed deletion must not remove note from list');
    assert.equal(elements.get('#note-form').hidden, false, 'failed deletion keeps editor open');
    assert.equal(deleteButton.disabled, false, 'failed deletion makes retry available');
    assert.equal(status.dataset.kind, 'error');
    assert.match(status.textContent, /삭제하지 못했습니다/u);
  } finally {
    globalThis.document = originalDocument;
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  }
});
