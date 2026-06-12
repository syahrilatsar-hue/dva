import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const TOKEN_EXPIRY_SECONDS = 60 * 60;

export function signAuthToken(payload, { expiresIn = TOKEN_EXPIRY_SECONDS } = {}) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyAuthToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

export function getTokenExpirySeconds() {
  return TOKEN_EXPIRY_SECONDS;
}

