const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const { ethers } = require('ethers');
const path     = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const CLOB_HOST   = 'https://clob.polymarket.com';
const GAMMA_HOST  = 'https://gamma-api.polymarket.com';
const DATA_HOST   = 'https://data-api.polymarket.com';
const CHAIN_ID    = 137;

let wallet = null;
let apiCreds = null;

function getWallet() {
  if (!wallet) {
    const pk = process.env.PRIVATE_KEY;
    if (!pk) throw new Error('PRIVATE_KEY not set');
    wallet = new ethers.Wallet(pk.startsWith('0x') ? pk : '0x' + pk);
  }
  return wallet;
}

function getFunder() {
  const f = process.env.FUNDER_ADDRESS;
  if (!f) throw new Error('FUNDER_ADDRESS not set');
  return f;
}

async function signL1Message(address, timestamp, nonce) {
  const w = getWallet();
  const domain = { name: 'ClobAuthDomain', version: '1', chainId: CHAIN_ID };
  const types = {
    ClobAuth: [
      { name: 'address',   type: 'address' },
      { name: 'timestamp', type: 'string'  },
      { name: 'nonce',     type: 'uint256' },
      { name: 'message',   type: 'string'  },
    ],
  };
  const value = {
    address, timestamp: String(timestamp), nonce,
    message: 'This message attests that I control the given wallet',
  };
  return await w._signTypedData(domain, types, value);
}

function buildL2Headers(method, path, body = '') {
  if (!apiCreds) throw new Error('Not authenticated');
  const ts  = Math.floor(Date.now() / 1000).toString();
  const msg = ts + method.toUpperCase() + path + (body ? JSON.stringify(body) : '');
  const sig = crypto.createHmac('sha256', Buffer.from(apiCreds.secret, 'base64')).update(msg).digest('base64');
  return {
    'Content-Type':    'application/json',
    'POLY_ADDRESS':    getWallet().address,
    'POLY_SIGNATURE':  sig,
    'POLY_TIMESTAMP':  ts,
    'POLY_API_KEY':    apiCreds.apiKey,
    'POLY_PASSPHRASE': apiCreds.passphrase,
  };
}

async function signOrder(orderData) {
  const w = getWallet();
  const domain = {
    name: 'Exchange', version: '1', chainId: CHAIN_ID,
    verifyingContract: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E',
  };
  const types = {
    Order: [
      { name: 'salt',          type: 'uint256' },
      { name: 'maker',         type: 'address' },
      { name: 'signer',        type: 'address' },
      { name: 'taker',         type: 'address' },
      { name: 'tokenId',       type: 'uint256' },
      { name: 'makerAmount',   type: 'uint256' },
      { name: 'takerAmount',   type: 'uint256' },
      { name: 'expiration',    type: 'uint256' },
      { name: 'nonce',         type: 'uint256' },
      { name: 'feeRateBps',    type: 'uint256' },
      { name: 'side',          type: 'uint8'   },
      { name: 'signatureType', type: 'uint8'   },
    ],
  };
  return await w._signTypedData(domain, types, orderData);
}

async function clobRequest(method, endpoint, body = null, auth = true) {
  const url = CLOB_HOST + endpoint;
  const opts = { method, headers: {} };
  if (auth) opts.headers = buildL2Headers(method, endpoint, body || '');
  else opts.headers['Content-Type'] = 'application/json';
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(`CLOB ${method} ${endpoint} → ${res.status}: ${text.substring(0,200)}`);
  return data;
}

app.post('/api/auth', async (req, res) => {
  try {
    const w = getWallet(), funder = getFunder();
    const timeData = await clobRequest('GET', '/time', null, false);
    const ts = timeData.time || Math.floor(Date.now() / 1000);
    const sig = await signL1Message(w.address, ts, 0);
    const credsRes = await fetch(`${CLOB_HOST}/auth/derive-api-key`, {
      method: 'GET',
      headers: { 'POLY_ADDRESS': w.address, 'POLY_SIGNATURE': sig, 'POLY_TIMESTAMP': String(ts), 'POLY_NONCE': '0' },
    });
    if (!credsRes.ok) throw new Error(`Auth failed: ${await credsRes.text()}`);
    apiCreds = await credsRes.json();
    res.json({ ok: true, address: w.address, funder, apiKey: apiCreds.apiKey });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/status', (req, res) => {
  res.json({
    configured: !!(process.env.PRIVATE_KEY && process.env.FUNDER_ADDRESS),
    authenticated: !!apiCreds,
    walletAddress: wallet?.address || null,
    funderAddress: process.env.FUNDER_ADDRESS || null,
  });
});

app.get('/api/balance', async (req, res) => {
  try {
    const funder = getFunder();
    const posData = await clobRequest('GET', `/positions?user=${funder}`, null, true).catch(() => []);
    const positions = Array.isArray(posData) ? posData : [];
    const openValue = positions.reduce((sum, p) => sum + (parseFloat(p.currentValue) || 0), 0);
    res.json({ ok: true, funder, openPositions: positions.length, openValue: openValue.toFixed(2) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/positions', async (req, res) => {
  try {
    const funder = getFunder();
    const data = await clobRequest('GET', `/positions?user=${funder}&sizeThreshold=0.01`, null, true);
    res.json({ ok: true, positions: Array.isArray(data) ? data : [] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/orders', async (req, res) => {
  try {
    const data = await clobRequest('GET', '/orders?status=LIVE', null, true);
    res.json({ ok: true, orders: Array.isArray(data) ? data : [] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/trades', async (req, res) => {
  try {
    const funder = getFunder();
    const data = await clobRequest('GET', `/trades?maker=${funder}&limit=50`, null, true);
    res.json({ ok: true, trades: Array.isArray(data) ? data : [] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/markets', async (req, res) => {
  try {
    const r = await fetch(`${GAMMA_HOST}/markets?active=true&closed=false&limit=100&order=volume24hr&ascending=false`);
    const data = await r.json();
    res.json({ ok: true, markets: Array.isArray(data) ? data : (data.markets || []) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/order', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated');
    const { tokenId, side, price, size, orderType = 'GTC' } = req.body;
    if (!tokenId) throw new Error('tokenId required');
    if (!['BUY','SELL'].includes(side)) throw new Error('side must be BUY or SELL');
    if (price <= 0 || price >= 1) throw new Error('price must be between 0 and 1');
    if (size < 1) throw new Error('minimum size is 1 USDC');
    if (size > 500) throw new Error('exceeds safety limit of 500 USDC');
    const w = getWallet(), funder = getFunder();
    let tickSize = '0.01';
    try { const ts = await clobRequest('GET', `/tick-size?token_id=${tokenId}`, null, false); tickSize = ts.minimum_tick_size || '0.01'; } catch {}
    const tick = parseFloat(tickSize);
    const priceR = Math.round(price / tick) * tick;
    const DECIMALS = 1e6, sideNum = side === 'BUY' ? 0 : 1;
    const salt = Math.floor(Math.random() * 1e15);
    let makerAmount, takerAmount;
    if (side === 'BUY') { makerAmount = Math.round(size * DECIMALS); takerAmount = Math.round((size / priceR) * DECIMALS); }
    else { makerAmount = Math.round(size * DECIMALS); takerAmount = Math.round(size * priceR * DECIMALS); }
    const orderStruct = {
      salt, maker: funder, signer: w.address,
      taker: '0x0000000000000000000000000000000000000000',
      tokenId: BigInt(tokenId), makerAmount: BigInt(makerAmount),
      takerAmount: BigInt(takerAmount), expiration: BigInt(0),
      nonce: BigInt(0), feeRateBps: BigInt(0), side: sideNum, signatureType: 0,
    };
    const signature = await signOrder(orderStruct);
    const orderPayload = {
      order: {
        salt: String(salt), maker: funder, signer: w.address,
        taker: '0x0000000000000000000000000000000000000000',
        tokenId, makerAmount: String(makerAmount), takerAmount: String(takerAmount),
        expiration: '0', nonce: '0', feeRateBps: '0',
        side, signatureType: 0, signature,
      },
      orderType, owner: funder,
    };
    const result = await clobRequest('POST', '/order', orderPayload, true);
    res.json({ ok: true, orderId: result.orderID, status: result.status, side, price: priceR.toFixed(2), size, tokenId, orderType });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/order/:orderId', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated');
    const result = await clobRequest('DELETE', `/order/${req.params.orderId}`, null, true);
    res.json({ ok: true, result });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/orders', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated');
    const result = await clobRequest('DELETE', '/orders', null, true);
    res.json({ ok: true, result });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/ping', (req, res) => res.json({ ok: true, ts: Date.now(), version: 'GLYPH v3.0' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`GLYPH POLYMARKET PRO v3.0 — port ${PORT}`);
  console.log(`PRIVATE_KEY: ${process.env.PRIVATE_KEY ? '✓ SET' : '✗ MISSING'}`);
  console.log(`FUNDER_ADDRESS: ${process.env.FUNDER_ADDRESS ? '✓ SET' : '✗ MISSING'}`);
});
