import { jwtVerify } from 'jose';

async function verifyToken(req) {
  const token = req.headers['x-session-token'] || '';
  if (!token) return false;
  try {
    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    await jwtVerify(token, secret);
    return true;
  } catch { return false; }
}

async function fetchSistema(url, serviceToken) {
  try {
    const res = await fetch(url, {
      headers: { 'x-service-token': serviceToken },
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const ok = await verifyToken(req);
  if (!ok) return res.status(401).json({ error: 'No autorizado' });

  const serviceToken = process.env.ABESA_SERVICE_TOKEN;

  const [zaifi, hausbrot, odsa] = await Promise.all([
    fetchSistema(process.env.ZAIFI_RESUMEN_URL, serviceToken),
    fetchSistema(process.env.HAUSBROT_RESUMEN_URL, serviceToken),
    fetchSistema(process.env.ODSA_RESUMEN_URL, serviceToken),
  ]);

  return res.status(200).json({
    ok: true,
    mes: new Date().toISOString().substring(0, 7),
    sistemas: { zaifi, hausbrot, odsa },
    consolidado: {
      ingresos: (zaifi?.ingresos || 0) + (hausbrot?.ingresos || 0) + (odsa?.ingresos || 0),
      gastos: (zaifi?.gastos || 0) + (hausbrot?.gastos || 0) + (odsa?.gastos || 0),
      resultado: (zaifi?.resultado || 0) + (hausbrot?.resultado || 0) + (odsa?.resultado || 0),
    }
  });
}
