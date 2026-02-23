import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../src/analyzer.js';

test('flags suspicious phishing URL as phishing', () => {
  const result = analyzeUrl('http://paypal-login-update.verify-account.xyz/security/session?token=123456789012345678901234567890');

  assert.equal(result.prediction, 'Phishing');
  assert.ok(result.confidence.phishing >= 55);
  assert.ok(result.reasons.length > 0);
});

test('classifies common legitimate URL as legitimate', () => {
  const result = analyzeUrl('https://www.wikipedia.org');

  assert.equal(result.prediction, 'Legitimate');
  assert.ok(result.confidence.legitimate > result.confidence.phishing);
});

test('throws for empty input', () => {
  assert.throws(() => analyzeUrl('  '), /Please provide a URL/);
});
