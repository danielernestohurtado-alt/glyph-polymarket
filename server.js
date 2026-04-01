const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const { ethers } = require('ethers');
const path     = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- CONFIG ----
const CLOB_HOST   = 'https://clob.polymarket.com';
const GAMMA_HOST  = 'https://gamma-api.polymarket.com';
const DATA_HOST   = 'https://data-api.polymarket.com';
const CHAIN_ID    = 137; // Polygon mainnet

// ---- WALLET + CREDENTIALS (loaded from Replit Secrets) ----
let wallet = null;
let apiCreds = null; // { apiKey, secret, passphrase }

function getWallet() {
  if (!wallet) {
    const pk = process.env.PRIVATE_KEY;
    if (!pk) throw new Error('PRIVATE_KEY not set in Replit Secrets');
    wallet = new ethers.Wallet(pk.startsWith('0x') ? pk : '0x' + pk);
  }
  return wallet;
}

function getFunder() {
  const f = process.env.FUNDER_ADDRESS;
  if (!f) throw new Error('FUNDER_ADDRESS not set in Replit Secrets');
  return f;
}

// ============================================================
// EIP-712 + HMAC SIGNING HELPERS
// ============================================================

// Generate EIP-712 signature for L1 auth (API key derivation)
async function signL1Message(address, timestamp, nonce) {
  const w = getWallet();

  const domain = {
    name: 'ClobAuthDomain',
    version: '1',
    chainId: CHAIN_ID,
  };

  const types = {
    ClobAuth: [
      { name: 'address',   type: 'address' },
      { name: 'timestamp', type: 'string'  },
      { name: 'nonce',     type: 'uint256' },
      { name: 'message',   type: 'string'  },
    ],
  };

  const value = {
    address:   address,
    timestamp: String(timestamp),
    nonce:     nonce,
    message:   'This message attests that I control the given wallet',
  };

  // ethers v5 _signTypedData
  return await w._signTypedData(domain, types, value);
}

// Generate HMAC-SHA256 L2 headers for authenticated requests
function buildL2Headers(method, path, body = '') {
  if (!apiCreds) throw new Error('API credentials not initialized. Call /api/auth first.');

  const ts  = Math.floor(Date.now() / 1000).toString();
  const msg = ts + method.toUpperCase() + path + (body ? JSON.stringify(body) : '');

  const sig = crypto
    .createHmac('sha256', Buffer.from(apiCreds.secret, 'base64'))
    .update(msg)
    .digest('base64');

  return {
    'Content-Type':    'application/json',
    'POLY_ADDRESS':    getWallet().address,
    'POLY_SIGNATURE':  sig,
    'POLY_TIMESTAMP':  ts,
    'POLY_API_KEY':    apiCreds.apiKey,
    'POLY_PASSPHRASE': apiCreds.passphrase,
  };
}

// Sign an order using EIP-712 (required for every trade)
async function signOrder(orderData) {
  const w = getWallet();

  const domain = {
    name:              'Exchange',
    version:           '1',
    chainId:           CHAIN_ID,
    verifyingContract: '0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E', // Polymarket exchange
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

  const sig = await w._signTypedData(domain, types, orderData);
  return sig;
}

// ============================================================
// CLOB HTTP HELPER
// ============================================================

async function clobRequest(method, endpoint, body = null, auth = true) {
  const url = CLOB_HOST + endpoint;
  const opts = { method, headers: {} };

  if (auth) {
    opts.headers = buildL2Headers(method, endpoint, body || '');
  } else {
    opts.headers['Content-Type'] = 'application/json';
  }

  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(url, opts);
  const text = await res.text();

  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!res.ok) {
    throw new Error(`CLOB ${method} ${endpoint} → ${res.status}: ${text.substring(0, 200)}`);
  }
  return data;
}

// ============================================================
// ROUTES — AUTH
// ============================================================

// POST /api/auth — derive or create API credentials from wallet
app.post('/api/auth', async (req, res) => {
  try {
    const w      = getWallet();
    const funder = getFunder();

    // Get server timestamp
    const timeData = await clobRequest('GET', '/time', null, false);
    const ts = timeData.time || Math.floor(Date.now() / 1000);
    const nonce = 0;

    // Sign L1 message
    const sig = await signL1Message(w.address, ts, nonce);

    // Derive API key
    const credsRes = await fetch(`${CLOB_HOST}/auth/derive-api-key`, {
      method: 'GET',
      headers: {
        'POLY_ADDRESS':   w.address,
        'POLY_SIGNATURE': sig,
        'POLY_TIMESTAMP': String(ts),
        'POLY_NONCE':     String(nonce),
      },
    });

    if (!credsRes.ok) {
      const err = await credsRes.text();
      throw new Error(`Auth failed: ${err}`);
    }

    apiCreds = await credsRes.json();

    res.json({
      ok:      true,
      address: w.address,
      funder:  funder,
      apiKey:  apiCreds.apiKey,
    });
  } catch (e) {
    console.error('[AUTH]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/status — check if authenticated + wallet info
app.get('/api/status', (req, res) => {
  const pk = process.env.PRIVATE_KEY;
  const fn = process.env.FUNDER_ADDRESS;
  const ak = process.env.ANTHROPIC_API_KEY;

  res.json({
    configured:          !!(pk && fn),
    authenticated:       !!apiCreds,
    walletAddress:       pk ? (wallet?.address || 'not loaded') : null,
    funderAddress:       fn || null,
    privateKeySet:       !!pk,
    funderAddressSet:    !!fn,
    anthropicKeySet:     !!ak,
  });
});

// ============================================================
// ROUTES — ACCOUNT
// ============================================================

// GET /api/balance — USDC balance and positions value
app.get('/api/balance', async (req, res) => {
  try {
    const funder = getFunder();

    // Get positions to compute total value
    const [posData, profileData] = await Promise.allSettled([
      clobRequest('GET', `/positions?user=${funder}`, null, true),
      fetch(`${DATA_HOST}/value?user=${funder}`).then(r => r.json()),
    ]);

    const positions = posData.status === 'fulfilled' ? (posData.value || []) : [];
    const profile   = profileData.status === 'fulfilled' ? profileData.value : {};

    // Compute open positions value
    const openValue = positions.reduce((sum, p) => {
      return sum + ((parseFloat(p.currentValue) || 0));
    }, 0);

    res.json({
      ok:          true,
      funder:      funder,
      openPositions: positions.length,
      openValue:   openValue.toFixed(2),
      totalValue:  profile.value || openValue.toFixed(2),
    });
  } catch (e) {
    console.error('[BALANCE]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/positions — open positions
app.get('/api/positions', async (req, res) => {
  try {
    const funder = getFunder();
    const data = await clobRequest('GET', `/positions?user=${funder}&sizeThreshold=0.01`, null, true);
    res.json({ ok: true, positions: Array.isArray(data) ? data : [] });
  } catch (e) {
    console.error('[POSITIONS]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/orders — open orders
app.get('/api/orders', async (req, res) => {
  try {
    const data = await clobRequest('GET', '/orders?status=LIVE', null, true);
    res.json({ ok: true, orders: Array.isArray(data) ? data : [] });
  } catch (e) {
    console.error('[ORDERS]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/trades — trade history
app.get('/api/trades', async (req, res) => {
  try {
    const funder = getFunder();
    const data = await clobRequest('GET', `/trades?maker=${funder}&limit=50`, null, true);
    res.json({ ok: true, trades: Array.isArray(data) ? data : [] });
  } catch (e) {
    console.error('[TRADES]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ============================================================
// ROUTES — MARKET DATA
// ============================================================

// GET /api/markets — top markets
app.get('/api/markets', async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const response = await fetch(
      `${GAMMA_HOST}/markets?active=true&closed=false&limit=${limit}&order=volume24hr&ascending=false`
    );
    const data = await response.json();
    res.json({ ok: true, markets: Array.isArray(data) ? data : (data.markets || []) });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/orderbook/:tokenId — live order book
app.get('/api/orderbook/:tokenId', async (req, res) => {
  try {
    const data = await clobRequest('GET', `/book?token_id=${req.params.tokenId}`, null, false);
    res.json({ ok: true, book: data });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/price/:tokenId — current price
app.get('/api/price/:tokenId', async (req, res) => {
  try {
    const side = req.query.side || 'BUY';
    const data = await clobRequest('GET', `/price?token_id=${req.params.tokenId}&side=${side}`, null, false);
    res.json({ ok: true, price: data });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ============================================================
// ROUTES — TRADING
// ============================================================

// POST /api/order — place a new order
// Body: { tokenId, side: "BUY"|"SELL", price, size, orderType: "GTC"|"FOK"|"GTD" }
app.post('/api/order', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated. Call /api/auth first.');

    const { tokenId, side, price, size, orderType = 'GTC' } = req.body;

    // Validate
    if (!tokenId) throw new Error('tokenId required');
    if (!['BUY', 'SELL'].includes(side)) throw new Error('side must be BUY or SELL');
    if (price <= 0 || price >= 1) throw new Error('price must be between 0 and 1');
    if (size < 1) throw new Error('size must be at least 1 USDC');
    if (size > 500) throw new Error('size exceeds safety limit of 500 USDC');

    const w      = getWallet();
    const funder = getFunder();

    // Get tick size for this market
    let tickSize = '0.01';
    try {
      const ts = await clobRequest('GET', `/tick-size?token_id=${tokenId}`, null, false);
      tickSize = ts.minimum_tick_size || '0.01';
    } catch {}

    // Round price to tick size
    const tick   = parseFloat(tickSize);
    const priceR = Math.round(price / tick) * tick;
    const priceStr = priceR.toFixed(tick < 0.01 ? 3 : 2);

    // Compute amounts (USDC has 6 decimals, tokens have 6 decimals on Polygon)
    const DECIMALS   = 1e6;
    const sideNum    = side === 'BUY' ? 0 : 1;
    const salt       = Math.floor(Math.random() * 1e15);
    const expiration = 0; // 0 = no expiry for GTC

    // For BUY: makerAmount = USDC spent, takerAmount = tokens received
    // For SELL: makerAmount = tokens sold, takerAmount = USDC received
    let makerAmount, takerAmount;
    if (side === 'BUY') {
      makerAmount = Math.round(size * DECIMALS);
      takerAmount = Math.round((size / priceR) * DECIMALS);
    } else {
      makerAmount = Math.round(size * DECIMALS);
      takerAmount = Math.round(size * priceR * DECIMALS);
    }

    const orderStruct = {
      salt:          salt,
      maker:         funder,
      signer:        w.address,
      taker:         '0x0000000000000000000000000000000000000000',
      tokenId:       BigInt(tokenId),
      makerAmount:   BigInt(makerAmount),
      takerAmount:   BigInt(takerAmount),
      expiration:    BigInt(expiration),
      nonce:         BigInt(0),
      feeRateBps:    BigInt(0),
      side:          sideNum,
      signatureType: 0, // EOA / MetaMask
    };

    const signature = await signOrder(orderStruct);

    // Build order payload
    const orderPayload = {
      order: {
        salt:          String(salt),
        maker:         funder,
        signer:        w.address,
        taker:         '0x0000000000000000000000000000000000000000',
        tokenId:       tokenId,
        makerAmount:   String(makerAmount),
        takerAmount:   String(takerAmount),
        expiration:    String(expiration),
        nonce:         '0',
        feeRateBps:    '0',
        side:          side,
        signatureType: 0,
        signature:     signature,
      },
      orderType,
      owner: funder,
    };

    const result = await clobRequest('POST', '/order', orderPayload, true);

    console.log(`[ORDER] ${side} ${size} USDC @ ${priceStr} | token:${tokenId} | ${result.orderID || 'unknown'}`);

    res.json({
      ok:       true,
      orderId:  result.orderID,
      status:   result.status,
      side,
      price:    priceStr,
      size,
      tokenId,
      orderType,
    });

  } catch (e) {
    console.error('[ORDER]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// DELETE /api/order/:orderId — cancel single order
app.delete('/api/order/:orderId', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated.');
    const result = await clobRequest('DELETE', `/order/${req.params.orderId}`, null, true);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// DELETE /api/orders — cancel all open orders
app.delete('/api/orders', async (req, res) => {
  try {
    if (!apiCreds) throw new Error('Not authenticated.');
    const result = await clobRequest('DELETE', '/orders', null, true);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ============================================================
// ROUTES — AI ANALYSIS (Claude Proxy)
// ============================================================

// POST /api/ai — proxy Claude API calls server-side (avoids CORS + protects API key)
app.post('/api/ai', async (req, res) => {
  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error('ANTHROPIC_API_KEY not set in Replit Secrets');
    }

    const { prompt } = req.body;
    if (!prompt) throw new Error('prompt is required');

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Anthropic API ${response.status}: ${errText.substring(0, 200)}`);
    }

    const data = await response.json();

    // Extract text from response blocks
    const text = (data.content || [])
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('\n');

    res.json({ ok: true, text });

  } catch (e) {
    console.error('[AI]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/ping', (req, res) => {
  res.json({ ok: true, ts: Date.now(), version: 'GLYPH v3.0' });
});

// ============================================================
// START
// ============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════╗
║   GLYPH POLYMARKET PRO v3.0          ║
║   Server running on port ${PORT}         ║
╠══════════════════════════════════════╣
║  PRIVATE_KEY:       ${process.env.PRIVATE_KEY       ? '✓ SET' : '✗ MISSING'}            ║
║  FUNDER_ADDRESS:    ${process.env.FUNDER_ADDRESS    ? '✓ SET' : '✗ MISSING'}            ║
║  ANTHROPIC_API_KEY: ${process.env.ANTHROPIC_API_KEY ? '✓ SET' : '✗ MISSING'}            ║
╚══════════════════════════════════════╝
  `);

  if (!process.env.PRIVATE_KEY || !process.env.FUNDER_ADDRESS) {
    console.warn('⚠  WARNING: Wallet secrets not set. Trading will fail.');
    console.warn('   Go to Replit → Secrets and add:');
    console.warn('   PRIVATE_KEY     = your Polymarket private key');
    console.warn('   FUNDER_ADDRESS  = your Polymarket proxy wallet address');
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('⚠  WARNING: ANTHROPIC_API_KEY not set. AI analysis will fail.');
    console.warn('   Go to Replit → Secrets and add:');
    console.warn('   ANTHROPIC_API_KEY = your Anthropic API key (sk-ant-...)');
  }
});
