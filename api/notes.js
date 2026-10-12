import { createClient } from '@supabase/supabase-js';

function unavailable(response) {
  return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
}

function keyFormat(secretKey) {
  if (!secretKey) return 'missing';
  if (secretKey.startsWith('sb_secret_')) return 'sb_secret';
  if (secretKey.startsWith('sb_publishable_')) return 'sb_publishable';
  return secretKey.split('.').length === 3 ? 'legacy_jwt' : 'other';
}

function reportDiagnostic({ supabaseUrl, secretKey, httpStatus, errorCode }) {
  const code = typeof errorCode === 'string' && /^[A-Za-z0-9_-]{1,32}$/u.test(errorCode)
    ? errorCode
    : httpStatus === 0 ? 'NETWORK_ERROR' : 'UNKNOWN';
  console.error('notes_api_supabase_diagnostic', {
    supabaseUrlPresent: Boolean(supabaseUrl),
    secretKeyPresent: Boolean(secretKey),
    keyFormat: keyFormat(secretKey),
    httpStatus: Number.isInteger(httpStatus) ? httpStatus : null,
    errorCode: code,
  });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
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

  try {
    const supabase = createClient(supabaseUrl, secretKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data, error, status } = await supabase.from('notes')
      .select('title,content')
      .order('created_at', { ascending: true })
      .order('id', { ascending: true })
      .limit(4);

    if (error) {
      reportDiagnostic({
        supabaseUrl,
        secretKey,
        httpStatus: status,
        errorCode: error.code,
      });
      return unavailable(response);
    }
    if (!Array.isArray(data)
        || data.some(note => typeof note.title !== 'string' || typeof note.content !== 'string')) {
      reportDiagnostic({
        supabaseUrl,
        secretKey,
        httpStatus: status,
        errorCode: 'INVALID_RESULT',
      });
      return unavailable(response);
    }
    return response.status(200).json({ notes: data });
  } catch {
    reportDiagnostic({
      supabaseUrl,
      secretKey,
      httpStatus: null,
      errorCode: 'CLIENT_OR_NETWORK_ERROR',
    });
    return unavailable(response);
  }
}
