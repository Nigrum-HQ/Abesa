import { createClient } from '@supabase/supabase-js';
import { SignJWT } from 'jose';
import bcrypt from 'bcrypt';
import { promisify } from 'util';

const bcryptCompare = promisify(bcrypt.compare);

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
    const { data: rows } = await supabase
      .from('abesa_usuarios')
      .select('*')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (!rows) return res.status(401).json({ error: 'Email o contrasena incorrectos' });

    const match = await bcryptCompare(password, rows.password_hash);
    if (!match) return res.status(401).json({ error: 'Email o contrasena incorrectos' });

    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    const token = await new SignJWT({ id: rows.id, email: rows.email, nombre: rows.nombre })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('8h')
      .sign(secret);

    return res.status(200).json({ ok: true, token, nombre: rows.nombre });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
