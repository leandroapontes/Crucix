import crypto from 'crypto';

const COOKIE_NAME = 'crucix_session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// Helper to sign the session cookie
function signCookie(value, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(value);
  return `${value}.${hmac.digest('hex')}`;
}

// Helper to verify the session cookie
function verifyCookie(signedValue, secret) {
  if (!signedValue || typeof signedValue !== 'string') return null;
  const parts = signedValue.split('.');
  if (parts.length !== 2) return null;
  const [value, signature] = parts;
  const expectedSignature = crypto.createHmac('sha256', secret).update(value).digest('hex');
  if (signature === expectedSignature) return value;
  return null;
}

export function authMiddleware(req, res, next) {
  const { AUTH_USERNAME, AUTH_PASSWORD, SESSION_SECRET } = process.env;

  // If auth is not configured, bypass
  if (!AUTH_USERNAME || !AUTH_PASSWORD || !SESSION_SECRET) {
    return next();
  }

  // Allow public paths (login page, login api, health check, static assets)
  const publicPaths = ['/login', '/login.html', '/api/health'];
  if (
    publicPaths.includes(req.path) || 
    req.path.match(/\.(css|png|jpg|jpeg|svg|ico|woff2?)$/) // Allow static assets for login page
  ) {
    return next();
  }

  // Parse cookies manually (no cookie-parser needed)
  const cookieHeader = req.headers.cookie || '';
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const parts = c.trim().split('=');
      return [parts[0], parts.slice(1).join('=')];
    })
  );

  const sessionCookie = cookies[COOKIE_NAME];
  if (!sessionCookie) {
    return res.redirect('/login');
  }

  const sessionData = verifyCookie(sessionCookie, SESSION_SECRET);
  if (sessionData !== 'authenticated') {
    return res.redirect('/login');
  }

  next();
}

export function handleLogin(req, res) {
  const { AUTH_USERNAME, AUTH_PASSWORD, SESSION_SECRET } = process.env;
  
  // If auth is not configured, just redirect to dashboard
  if (!AUTH_USERNAME || !AUTH_PASSWORD || !SESSION_SECRET) {
    return res.redirect('/');
  }

  const { username, password } = req.body || {};

  if (username === AUTH_USERNAME && password === AUTH_PASSWORD) {
    const signedValue = signCookie('authenticated', SESSION_SECRET);
    res.cookie(COOKIE_NAME, signedValue, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: SESSION_MAX_AGE,
      sameSite: 'lax'
    });
    return res.redirect('/');
  }

  // Error case: Send them back to the login page with a generic error
  res.redirect('/login?error=1');
}

export function handleLogout(req, res) {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/login');
}
