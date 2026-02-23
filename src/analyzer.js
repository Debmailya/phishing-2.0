const SHORTENER_HOSTS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly'
]);

const SUSPICIOUS_TERMS = [
  'login', 'verify', 'secure', 'update', 'account', 'wallet', 'bank', 'support', 'microsoft', 'apple', 'paypal'
];

const TRUSTED_TLDS = new Set(['.com', '.org', '.net', '.io', '.edu', '.gov']);

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

function normalizedUrl(input) {
  const candidate = input.trim();
  if (!candidate) {
    throw new Error('Please provide a URL.');
  }

  const withProtocol = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
  const parsed = new URL(withProtocol);

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP/HTTPS URLs are supported.');
  }

  return parsed;
}

export function analyzeUrl(input) {
  const parsed = normalizedUrl(input);
  const host = parsed.hostname.toLowerCase();
  const full = parsed.toString();

  const reasons = [];
  let riskScore = 5;

  if (host.includes('@')) {
    riskScore += 30;
    reasons.push('URL contains "@" which can hide the real destination.');
  }

  if (/\d+\.\d+\.\d+\.\d+/.test(host)) {
    riskScore += 20;
    reasons.push('Hostname is a raw IP address instead of a branded domain.');
  }

  if (host.split('.').length > 4) {
    riskScore += 16;
    reasons.push('Domain contains excessive subdomains, a common obfuscation tactic.');
  }

  if (host.includes('-')) {
    riskScore += 8;
    reasons.push('Hyphenated domain patterns are often used in impersonation attacks.');
  }

  if (SHORTENER_HOSTS.has(host)) {
    riskScore += 30;
    reasons.push('URL shortener detected, which can conceal malicious targets.');
  }

  const looksLikeLegitBrand = /paypal|google|microsoft|apple|amazon|meta|bank/i.test(full);
  const suspiciousTermsCount = SUSPICIOUS_TERMS.filter((term) => full.toLowerCase().includes(term)).length;

  if (suspiciousTermsCount >= 3) {
    riskScore += 18;
    reasons.push('Multiple high-risk phishing keywords were found in the URL path.');
  }

  if (looksLikeLegitBrand && !host.endsWith('.com')) {
    riskScore += 15;
    reasons.push('Brand-like language appears on a non-standard domain extension.');
  }

  if (!TRUSTED_TLDS.has(`.${host.split('.').pop()}`)) {
    riskScore += 10;
    reasons.push('Domain uses an uncommon TLD often abused for phishing campaigns.');
  }

  if (parsed.pathname.length > 80 || parsed.search.length > 120) {
    riskScore += 12;
    reasons.push('Very long URL path/query indicates possible payload obfuscation.');
  }

  if (parsed.protocol === 'https:') {
    riskScore -= 4;
  } else {
    riskScore += 10;
    reasons.push('Unencrypted HTTP was detected, increasing exposure risk.');
  }

  riskScore = clamp(riskScore, 1, 99);

  const phishingProbability = clamp(Math.round(riskScore), 1, 99);
  const legitimateProbability = 100 - phishingProbability;
  const prediction = phishingProbability >= 55 ? 'Phishing' : 'Legitimate';

  let threatLevel = 'Low';
  if (phishingProbability >= 85) threatLevel = 'Critical';
  else if (phishingProbability >= 70) threatLevel = 'High';
  else if (phishingProbability >= 55) threatLevel = 'Medium';

  if (reasons.length === 0) {
    reasons.push('No strong phishing signals detected by the AI risk engine.');
  }

  return {
    scannedUrl: parsed.toString(),
    domain: host,
    prediction,
    threatLevel,
    confidence: {
      phishing: phishingProbability,
      legitimate: legitimateProbability
    },
    reasons,
    analyzedAt: new Date().toISOString()
  };
}
