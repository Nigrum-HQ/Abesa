import { createClient } from '@supabase/supabase-js';
import { SignJWT } from 'jose';

const supabase = createClient(
  process.env.SUPA_URL,
  process.env.SUPA_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const { data, error } = await supabase.rpc('verificar_usuario_abesa', {
      p_email: email.toLowerCase().trim(),
      p_password: password
    });

    if (error || !data || data.length === 0) {
      return res.status(401).json({ error: 'Email o contrasena incorrectos' });
    }

    const usuario = data[0];
    if (!usuario.ok) {
      return res.status(401).json({ error: 'Email o contrasena incorrectos' });
    }

    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    const token = await new SignJWT({ id: usuario.id, email: usuario.email, nombre: usuario.nombre })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('8h')
      .sign(secret);

    return res.status(200).json({ ok: true, token, nombre: usuario.nombre });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
