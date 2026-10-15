#!/usr/bin/env bun
/**
 * PlainSight — local-first security checkup for small business websites.
 *
 * Usage:
 *   bun plainsight.ts scan <domain>            Run passive checks, print findings JSON
 *   bun plainsight.ts report <findings.json>   Generate plain-English report via local Ollama
 *   bun plainsight.ts checkup <domain>         scan + report in one step -> checkup-<domain>.md
 *
 * All checks are passive: normal HTTPS requests and DNS lookups only, the same
 * traffic any visitor's browser generates. Run this only against domains you
 * own or have written permission to assess.
 */

import tls from 'node:tls';
import { resolveTxt, resolveMx, resolve4 } from 'node:dns/promises';
import { writeFile } from 'node:fs/promises';

// ---------- types ----------

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  detail: string;
  plainWhy: string;   // one-line hint for the report writer
  fixHint: string;
}

interface ScanResult {
  domain: string;
  scannedAt: string;
  reachable: boolean;
  findings: Finding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number };
}

const UA = 'PlainSight/0.1 (+https://github.com/blueeyez425-art/plainsight)';

// ---------- helpers ----------

async function timedFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      redirect: 'manual',
      ...opts,
      signal: ctrl.signal,
      headers: { 'user-agent': UA, ...(opts.headers || {}) },
    });
  } finally {
    clearTimeout(t);
  }
}

function getTlsCert(host: string): Promise<{ daysLeft: number; issuer: string; valid: boolean } | null> {
  return new Promise((resolve) => {
    const sock = tls.connect(443, host, { servername: host, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      if (!cert || !cert.valid_to) return resolve(null);
      const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
      resolve({
        daysLeft,
        issuer: String(cert.issuer?.O || cert.issuer?.CN || 'unknown'),
        valid: daysLeft >= 0,
      });
    });
    sock.setTimeout(8000, () => { sock.destroy(); resolve(null); });
    sock.on('error', () => resolve(null));
  });
}

async function txtOrNull(name: string): Promise<string[] | null> {
  try {
    const records = await resolveTxt(name);
    return records.map((r) => r.join(''));
  } catch {
    return null;
  }
}

// ---------- checks ----------

async function scan(domain: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const add = (f: Finding) => findings.push(f);

  // 1. HTTPS reachability + headers
  let res: Response | null = null;
  let html = '';
  try {
    res = await timedFetch(`https://${domain}/`);
    html = await res.text();
  } catch {
    // fall back to http
    try {
      const httpRes = await timedFetch(`http://${domain}/`);
      await httpRes.text();
      add({
        id: 'no-https', title: 'Website does not use HTTPS', severity: 'high',
        detail: `https://${domain} failed to respond; the site was reachable over plain HTTP only.`,
        plainWhy: 'Anything customers type into the site travels in plain text that others on the network can read.',
        fixHint: 'Enable HTTPS with a free certificate (e.g. via your host or Cloudflare) and redirect all traffic to it.',
      });
    } catch {
      return finalize(domain, findings, false);
    }
  }

  if (res) {
    const h = res.headers;
    const headerChecks: Array<[string, string, Severity, string, string]> = [
      ['strict-transport-security', 'Missing HSTS header', 'low',
        'Browsers are not told to always use the secure version of the site, which leaves room for downgrade tricks on public Wi-Fi.',
        'Add a Strict-Transport-Security header (most hosts have a one-click setting).'],
      ['content-security-policy', 'Missing Content-Security-Policy header', 'medium',
        'Without a content policy, a single injected script (e.g. through a vulnerable plugin) can skim customer data from pages.',
        'Add a Content-Security-Policy header starting restrictive and loosening as needed.'],
      ['x-frame-options', 'Missing X-Frame-Options header', 'low',
        'The site can be embedded inside a look-alike page (clickjacking) to trick visitors into clicking things they cannot see.',
        'Set X-Frame-Options: DENY or SAMEORIGIN.'],
      ['x-content-type-options', 'Missing X-Content-Type-Options header', 'low',
        'Browsers may misinterpret uploaded files, a small but real opening for certain attacks.',
        'Set X-Content-Type-Options: nosniff.'],
      ['referrer-policy', 'Missing Referrer-Policy header', 'info',
        'The site may leak which page a visitor came from when they click outbound links.',
        'Set Referrer-Policy: strict-origin-when-cross-origin.'],
    ];
    for (const [name, title, sev, why, fix] of headerChecks) {
      if (!h.get(name)) {
        add({ id: `missing-${name}`, title, severity: sev as Severity, detail: `Response from https://${domain}/ does not include the ${name} header.`, plainWhy: why, fixHint: fix });
      }
    }

    const server = h.get('server');
    const powered = h.get('x-powered-by');
    if (powered || (server && /[\d.]/.test(server))) {
      add({
        id: 'tech-disclosure', title: 'Server technology is advertised in headers', severity: 'info',
        detail: `Headers disclose: ${[server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join('; ')}`,
        plainWhy: 'Broadcasting exact software versions saves attackers time when searching for known weaknesses.',
        fixHint: 'Configure the server/framework to suppress version details in response headers.',
      });
    }

    // cookies without Secure/HttpOnly
    const setCookies = (h.getSetCookie?.() ?? []) as string[];
    const weakCookies = setCookies.filter((c) => !/secure/i.test(c) || !/httponly/i.test(c));
    if (weakCookies.length > 0) {
      add({
        id: 'weak-cookies', title: `${weakCookies.length} cookie(s) missing Secure/HttpOnly flags`, severity: 'low',
        detail: `Example: ${weakCookies[0].split(';')[0]}...`,
        plainWhy: 'Session cookies without these flags are easier to steal through script injection or network snooping.',
        fixHint: 'Set Secure and HttpOnly on all session cookies (a server/framework config change).',
      });
    }

    // mixed content
    const mixed = html.match(/(?:src|href)=["']http:\/\/[^"']+["']/gi) || [];
    if (mixed.length > 0) {
      add({
        id: 'mixed-content', title: `${mixed.length} insecure (http://) resource(s) loaded on the homepage`, severity: 'medium',
        detail: `Examples: ${[...new Set(mixed)].slice(0, 3).join(', ')}`,
        plainWhy: 'Insecure scripts or images on a secure page can be swapped out by someone on the network.',
        fixHint: 'Update all resource URLs to https:// (often a theme/plugin setting).',
      });
    }
  }

  // 2. HTTP -> HTTPS redirect
  try {
    const r = await timedFetch(`http://${domain}/`);
    const loc = r.headers.get('location') || '';
    if (r.status >= 200 && r.status < 400 && !loc.startsWith('https://')) {
      add({
        id: 'no-https-redirect', title: 'HTTP does not redirect to HTTPS', severity: 'medium',
        detail: `http://${domain}/ returned status ${r.status}${loc ? ` with Location: ${loc}` : ' (served directly)'}.`,
        plainWhy: 'Visitors typing the plain address get an unprotected page instead of being sent to the secure one.',
        fixHint: 'Force an HTTP→HTTPS redirect at the host or CDN level.',
      });
    }
  } catch { /* no http listener at all is fine */ }

  // 3. TLS certificate
  const cert = await getTlsCert(domain);
  if (cert) {
    if (!cert.valid) {
      add({ id: 'tls-expired', title: 'TLS certificate is EXPIRED', severity: 'critical', detail: `Certificate expired ${-cert.daysLeft} days ago (issuer: ${cert.issuer}).`, plainWhy: 'Browsers now warn every visitor the site may be unsafe — most people leave.', fixHint: 'Renew the certificate immediately (usually automatic via the host).' });
    } else if (cert.daysLeft <= 14) {
      add({ id: 'tls-expiring', title: `TLS certificate expires in ${cert.daysLeft} day(s)`, severity: 'medium', detail: `Certificate (issuer: ${cert.issuer}) expires very soon.`, plainWhy: 'If it lapses, browsers will warn every visitor away.', fixHint: 'Confirm auto-renewal is enabled or renew manually now.' });
    }
  }

  // 4. Email authentication (SPF / DMARC / MX)
  const [spf, dmarc, mx] = await Promise.all([txtOrNull(domain), txtOrNull(`_dmarc.${domain}`), resolveMx(domain).catch(() => null)]);
  const spfRec = spf?.find((t) => t.startsWith('v=spf1'));
  const dmarcRec = dmarc?.find((t) => t.startsWith('v=DMARC1'));

  if (mx && mx.length > 0) {
    if (!spfRec) {
      add({ id: 'no-spf', title: 'No SPF record for the domain', severity: 'high', detail: `The domain accepts mail but publishes no SPF record.`, plainWhy: 'Anyone on the internet can send email that looks like it comes from this business — invoices, payment changes, anything.', fixHint: 'Publish an SPF TXT record listing only your real mail providers.' });
    } else if (spfRec.includes('+all')) {
      add({ id: 'spf-allow-all', title: 'SPF record allows ANY server to send mail', severity: 'high', detail: `SPF record: "${spfRec}" — the +all mechanism authorizes every server on the internet.`, plainWhy: 'This is equivalent to having no protection: scammers can spoof the business address freely.', fixHint: 'Replace +all with ~all or -all and list only legitimate senders.' });
    }
    if (!dmarcRec) {
      add({ id: 'no-dmarc', title: 'No DMARC record for the domain', severity: 'high', detail: `No _dmarc.${domain} TXT record found.`, plainWhy: 'Even with other protections, mail providers get no instructions to reject fake messages from this domain.', fixHint: 'Publish a DMARC record (start with p=quarantine plus a reporting address, then move to p=reject).' });
    } else if (/p=none/.test(dmarcRec)) {
      add({ id: 'dmarc-none', title: 'DMARC policy is set to "none" (monitor only)', severity: 'medium', detail: `DMARC record: "${dmarcRec}"`, plainWhy: 'Spoofed mail is being watched, not blocked — fake invoices still reach customers.', fixHint: 'Move the policy to p=quarantine, then p=reject, after reviewing reports.' });
    }
  }

  // 5. Commonly exposed sensitive files (single polite GET each)
  const probes: Array<[string, RegExp, string, Severity, string]> = [
    ['/.git/HEAD', /^ref:/, 'Exposed .git directory', 'critical', 'The entire source code — including passwords and keys committed to it — is downloadable by anyone.'],
    ['/.env', /^\s*[A-Z_]{2,}\s*=/m, 'Exposed .env file', 'critical', 'Environment files usually contain live database passwords and API keys.'],
    ['/wp-config.php.bak', /DB_PASSWORD/i, 'Exposed WordPress config backup', 'critical', 'Backup copies of wp-config.php expose the database password in plain text.'],
    ['/server-status', /Server uptime|Apache Status/i, 'Exposed server-status page', 'medium', 'Status pages leak internal URLs, visitor IPs, and server details useful to attackers.'],
    ['/.DS_Store', /Bud1/, 'Exposed .DS_Store file', 'low', 'Mac metadata files reveal the directory layout of the site.'],
  ];
  for (const [path, sig, title, sev, why] of probes) {
    try {
      const r = await timedFetch(`https://${domain}${path}`, {}, 6000);
      if (r.status === 200) {
        const body = (await r.text()).slice(0, 4096);
        if (sig.test(body)) {
          add({ id: `exposed-${path.replace(/[^a-z]/gi, '')}`, title, severity: sev as Severity, detail: `https://${domain}${path} returns HTTP 200 with content matching the expected signature.`, plainWhy: why, fixHint: `Remove or block access to ${path} at the server level, and rotate any credentials it may have contained.` });
        }
      }
    } catch { /* unreachable path — fine */ }
  }

  // 6. Positive signal: security.txt
  try {
    const r = await timedFetch(`https://${domain}/.well-known/security.txt`, {}, 5000);
    if (r.status !== 200) {
      add({ id: 'no-security-txt', title: 'No security.txt contact file', severity: 'info', detail: 'No /.well-known/security.txt found.', plainWhy: 'When a researcher finds a real problem, there is no published way to tell the business privately.', fixHint: 'Publish a short security.txt with a contact email (free generator at securitytxt.org).' });
    }
  } catch { /* ignore */ }

  return finalize(domain, findings, true);
}

function finalize(domain: string, findings: Finding[], reachable: boolean): ScanResult {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const summary = Object.fromEntries(order.map((s) => [s, findings.filter((f) => f.severity === s).length])) as ScanResult['summary'];
  return { domain, scannedAt: new Date().toISOString(), reachable, findings, summary };
}

// ---------- report generation (local open-weight model via Ollama) ----------

const OLLAMA = process.env.OLLAMA_HOST || 'http://localhost:11434';
const MODEL = process.env.OLLAMA_MODEL || 'llama3.1:8b';

function buildPrompt(scan: ScanResult): string {
  return [
    'You are a friendly, calm security consultant writing a one-page checkup report for a small business owner',
    'who has NO technical background. Rules:',
    '- Never use jargon without immediately explaining it in plain words.',
    '- No alarmism. Be factual, warm, and practical.',
    '- For each finding: what it is (one plain sentence), why it matters (one sentence, business impact), how to fix it (one sentence, in terms a web developer or hosting provider can act on).',
    '- Group findings under headings: "Fix these first", "Worth fixing soon", "Good to know".',
    '- Start with a 2-3 sentence plain-English summary and end with one encouraging sentence.',
    '- Output Markdown only.',
    '',
    `Domain checked: ${scan.domain}`,
    `Date: ${scan.scannedAt.slice(0, 10)}`,
    '',
    'Findings (JSON):',
    JSON.stringify(scan.findings.map(({ title, severity, detail, plainWhy, fixHint }) => ({ title, severity, detail, why: plainWhy, fix: fixHint })), null, 2),
  ].join('\n');
}

async function generateReport(scan: ScanResult): Promise<string> {
  const prompt = buildPrompt(scan);
  const resp = await fetch(`${OLLAMA}/api/generate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: MODEL, prompt, stream: false }),
  });
  if (!resp.ok) throw new Error(`Ollama returned ${resp.status}: ${await resp.text()}`);
  const data = await resp.json() as { response: string };
  return [
    `# Security Checkup — ${scan.domain}`,
    ``,
    `*Prepared by PlainSight. Report written locally by ${MODEL} — no data left this machine.*`,
    ``,
    data.response.trim(),
    ``,
    `---`,
    `*Raw findings: ${scan.summary.critical} critical, ${scan.summary.high} high, ${scan.summary.medium} medium, ${scan.summary.low} low, ${scan.summary.info} informational.*`,
  ].join('\n');
}

// ---------- cli ----------

const [cmd, arg] = process.argv.slice(2);

if (!cmd || !arg || !['scan', 'report', 'checkup'].includes(cmd)) {
  console.error('Usage: bun plainsight.ts <scan|report|checkup> <domain|findings.json>');
  process.exit(1);
}

if (cmd === 'scan') {
  const result = await scan(arg);
  console.log(JSON.stringify(result, null, 2));
} else if (cmd === 'report') {
  const raw = JSON.parse(await (await import('node:fs/promises')).readFile(arg, 'utf8')) as ScanResult;
  console.log(await generateReport(raw));
} else {
  const result = await scan(arg);
  if (!result.reachable) {
    console.error(`Could not reach ${arg} over HTTP or HTTPS.`);
    process.exit(2);
  }
  const findingsPath = `findings-${arg.replace(/[^a-z0-9]/gi, '_')}.json`;
  await writeFile(findingsPath, JSON.stringify(result, null, 2));
  console.error(`Scanned ${arg}: ${JSON.stringify(result.summary)}. Generating report with ${MODEL}...`);
  const report = await generateReport(result);
  const outPath = `checkup-${arg.replace(/[^a-z0-9]/gi, '_')}.md`;
  await writeFile(outPath, report);
  console.log(report);
  console.error(`\nSaved: ${outPath} (findings: ${findingsPath})`);
}
