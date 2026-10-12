import { createClient } from '@supabase/supabase-js';

function unavailable(response) {
  return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) return unavailable(response);

  try {
    const supabaseFetch = secretKey.startsWith('sb_secret_')
      ? (input, init) => {
        const headers = new Headers(init?.headers);
        headers.delete('Authorization');
        return globalThis.fetch(input, { ...init, headers });
      }
      : globalThis.fetch;
    const supabase = createClient(supabaseUrl, secretKey, {
      auth: { autoRefreshToken: false, persistSession: false },
      global: { fetch: supabaseFetch },
    });
    const { data, error } = await supabase.from('notes')
      .select('title,content')
      .order('created_at', { ascending: true })
      .order('id', { ascending: true })
      .limit(4);

    if (error || !Array.isArray(data)
        || data.some(note => typeof note.title !== 'string' || typeof note.content !== 'string')) {
      return unavailable(response);
    }
    return response.status(200).json({ notes: data });
  } catch {
    return unavailable(response);
  }
}
