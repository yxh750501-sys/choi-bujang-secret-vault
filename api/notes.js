import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu;
const TITLE_MAX_LENGTH = 200;
const BODY_MAX_LENGTH = 20000;

function jsonError(response, status, error) {
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json({ error });
}

function noteBody(request) {
  if (typeof request.body === 'string') {
    try {
      return JSON.parse(request.body);
    } catch {
      return null;
    }
  }
  return request.body;
}

function validNoteFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || (value.id !== undefined && (typeof value.id !== 'string' || !UUID.test(value.id)))
      || typeof value.title !== 'string' || !value.title.trim()
      || value.title.trim().length > TITLE_MAX_LENGTH
      || typeof value.body !== 'string' || !value.body.trim()
      || value.body.length > BODY_MAX_LENGTH) return false;
  return true;
}

function noteFromRow(row) {
  return { id: row.id, title: row.title, body: row.content };
}

function unavailable(response) {
  return jsonError(response, 503, 'NOTES_UNAVAILABLE');
}

function reportDiagnostic({ supabaseUrl, secretKey, httpStatus, errorCode }) {
  const code = typeof errorCode === 'string' && /^[A-Za-z0-9_-]{1,32}$/u.test(errorCode)
    ? errorCode
    : httpStatus === 0 ? 'NETWORK_ERROR' : 'UNKNOWN';
  console.error('notes_api_supabase_diagnostic', {
    supabaseUrlPresent: Boolean(supabaseUrl),
    secretKeyPresent: Boolean(secretKey),
    httpStatus: Number.isInteger(httpStatus) ? httpStatus : null,
    errorCode: code,
  });
}

export function createNotesHandler({ verifierFactory = createLoginVerifier, verifierConfig = config } = {}) {
  let verifyAuthorization;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    const method = request.method;
    const pathId = request.query?.id;
    const hasId = pathId !== undefined;
    const supported = hasId ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
    if (!supported.includes(method)) {
      response.setHeader('Allow', supported.join(', '));
      return jsonError(response, 405, 'METHOD_NOT_ALLOWED');
    }

    const authorization = request.headers?.authorization ?? request.headers?.Authorization;
    if (typeof authorization !== 'string' || !authorization.trim()) {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const secretKey = process.env.SUPABASE_SECRET_KEY;
    if (!supabaseUrl || !secretKey) {
      reportDiagnostic({
        supabaseUrl,
        secretKey,
        httpStatus: null,
        errorCode: 'ENV_MISSING',
      });
      return unavailable(response);
    }

    let identity;
    try {
      verifyAuthorization ??= verifierFactory({
        config: verifierConfig,
        supabaseSecretKey: secretKey,
      });
      identity = await verifyAuthorization(authorization);
    } catch {
      reportDiagnostic({
        supabaseUrl,
        secretKey,
        httpStatus: null,
        errorCode: 'AUTH_VERIFIER_ERROR',
      });
      return unavailable(response);
    }
    if (!identity || typeof identity.userId !== 'string') {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }
    if (hasId && (typeof pathId !== 'string' || !UUID.test(pathId))) {
      return jsonError(response, 400, 'INVALID_NOTE_ID');
    }

    const body = ['POST', 'PUT'].includes(method) ? noteBody(request) : null;
    if (method === 'POST' && !validNoteFields(body)) return jsonError(response, 400, 'INVALID_NOTE');
    if (method === 'PUT' && !validNoteFields(body)) return jsonError(response, 400, 'INVALID_NOTE');

    try {
      const supabase = createClient(supabaseUrl, secretKey, {
        auth: { autoRefreshToken: false, persistSession: false },
      });
      let result;
      if (!hasId && method === 'GET') {
        result = await supabase.from('notes')
          .select('id,title,content')
          .eq('owner_id', identity.userId)
          .order('created_at', { ascending: true })
          .order('id', { ascending: true });
        if (!result.error && Array.isArray(result.data)
            && result.data.every(note => typeof note.id === 'string'
              && typeof note.title === 'string' && typeof note.content === 'string')) {
          return response.status(200).json({ notes: result.data.map(noteFromRow) });
        }
      } else if (!hasId && method === 'POST') {
        const id = body.id ?? randomUUID();
        result = await supabase.from('notes')
          .insert({
            id,
            owner_id: identity.userId,
            title: body.title.trim(),
            content: body.body,
          })
          .select('id')
          .single();
        if (!result.error && result.data?.id === id) {
          return response.status(201).json({ id });
        }
      } else if (hasId && method === 'GET') {
        result = await supabase.from('notes')
          .select('id,title,content')
          .eq('id', pathId)
          .eq('owner_id', identity.userId)
          .maybeSingle();
        if (!result.error && !result.data) return jsonError(response, 404, 'NOTE_NOT_FOUND');
        if (!result.error && typeof result.data?.id === 'string'
            && typeof result.data.title === 'string' && typeof result.data.content === 'string') {
          return response.status(200).json(noteFromRow(result.data));
        }
      } else if (hasId && method === 'PUT') {
        result = await supabase.from('notes')
          .update({ title: body.title.trim(), content: body.body })
          .eq('id', pathId)
          .eq('owner_id', identity.userId)
          .select('id,title,content')
          .maybeSingle();
        if (!result.error && !result.data) return jsonError(response, 404, 'NOTE_NOT_FOUND');
        if (!result.error && typeof result.data?.id === 'string'
            && typeof result.data.title === 'string' && typeof result.data.content === 'string') {
          return response.status(200).json(noteFromRow(result.data));
        }
      } else if (hasId && method === 'DELETE') {
        result = await supabase.from('notes')
          .delete()
          .eq('id', pathId)
          .eq('owner_id', identity.userId)
          .select('id')
          .maybeSingle();
        if (!result.error && !result.data) return jsonError(response, 404, 'NOTE_NOT_FOUND');
        if (!result.error && result.data?.id === pathId) {
          return response.status(200).json({ id: pathId });
        }
      }

      if (result?.error) {
        reportDiagnostic({
          supabaseUrl,
          secretKey,
          httpStatus: result.status,
          errorCode: result.error.code,
        });
      } else {
        reportDiagnostic({
          supabaseUrl,
          secretKey,
          httpStatus: result?.status,
          errorCode: 'INVALID_RESULT',
        });
      }
      return unavailable(response);
    } catch {
      reportDiagnostic({
        supabaseUrl,
        secretKey,
        httpStatus: null,
        errorCode: 'CLIENT_OR_NETWORK_ERROR',
      });
      return unavailable(response);
    }
  };
}

export default createNotesHandler();
