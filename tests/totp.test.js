const test = require('node:test');
const assert = require('node:assert/strict');
const speakeasy = require('speakeasy');

test('speakeasy TOTP token verifies with base32 secret', () => {
  const secret = speakeasy.generateSecret({ length: 20 });
  const token = speakeasy.totp({ secret: secret.base32, encoding: 'base32' });

  const verified = speakeasy.totp.verify({
    secret: secret.base32,
    encoding: 'base32',
    token,
    window: 1
  });

  assert.equal(verified, true);
});
