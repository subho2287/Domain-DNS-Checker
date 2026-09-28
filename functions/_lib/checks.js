// DNS / mail / security checks using DNS-over-HTTPS and fetch (Workers-compatible).
import { records, txt, query, unquoteTxt } from './doh.js';

const mk = (category, test, status, info) => ({ category, test, status, info });

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const isPrivateIp = (ip) =>
  /^10\./.test(ip) ||
  /^192\.168\./.test(ip) ||
  /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
  /^127\./.test(ip) ||
  /^169\.254\./.test(ip) ||
  /^0\./.test(ip);

const clean = (h) => h.toLowerCase().replace(/\.$/, '');

function rangeStatus(v, min, max) {
  const n = Number(v);
  if (Number.isNaN(n)) return 'info';
  return n >= min && n <= max ? 'pass' : 'warn';
}
function rangeInfo(label, v, min, max, note) {
  const n = Number(v);
  const ok = n >= min && n <= max;
  return `${label} is <strong>${v}</strong> seconds. ${ok ? 'This is within the recommended range.' : `Recommended range is ${min}\u2013${max} seconds.`} ${note}`;
}

async function httpProbe(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', headers: { 'user-agent': 'DNSChecker/1.0' } });
    return { status: res.status, headers: res.headers, location: res.headers.get('location') };
  } catch (err) {
    return { error: err.message || 'request failed' };
  }
}

export async function runChecks(rawDomain) {
  const domain = String(rawDomain || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');

  if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(domain)) {
    throw new Error('Please enter a valid domain name, e.g. example.com');
  }

  const results = [];

  // ---- Gather ---------------------------------------------------------------
  const ns = (await records(domain, 'NS')).map(clean);
  const soaRaw = (await records(domain, 'SOA'))[0] || null;
  const mxRaw = await records(domain, 'MX');
  const apexA = await records(domain, 'A');
  const apexAAAA = await records(domain, 'AAAA');
  const wwwA = await records(`www.${domain}`, 'A');
  const wwwAAAA = await records(`www.${domain}`, 'AAAA');
  const wwwCname = (await records(`www.${domain}`, 'CNAME')).map(clean)[0] || null;
  const caa = await records(domain, 'CAA');

  const txtAll = await txt(domain);
  const spfRecords = txtAll.filter((r) => /^v=spf1/i.test(r));
  const spf = spfRecords[0] || null;
  const dmarc = (await txt(`_dmarc.${domain}`)).find((r) => /^v=DMARC1/i.test(r)) || null;
  const mtaSts = (await txt(`_mta-sts.${domain}`)).find((r) => /v=STSv1/i.test(r)) || null;
  const tlsRpt = (await txt(`_smtp._tls.${domain}`)).find((r) => /v=TLSRPTv1/i.test(r)) || null;
  const bimi = (await txt(`default._bimi.${domain}`)).find((r) => /v=BIMI1/i.test(r)) || null;

  // NS -> IPs
  const nsIpMap = {};
  for (const n of ns) {
    const a = (await records(n, 'A'))[0];
    if (a) nsIpMap[n] = a;
  }

  // DKIM common selectors
  const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'dkim', 'mail', 'smtp'];
  const dkim = [];
  for (const sel of DKIM_SELECTORS) {
    const rec = (await txt(`${sel}._domainkey.${domain}`)).find((r) => /v=DKIM1|(^|;)\s*p=[A-Za-z0-9+/]/i.test(r));
    if (rec) dkim.push(sel);
  }

  // Wildcard
  const wildcard = (await records(`nx-${Math.random().toString(36).slice(2, 12)}.${domain}`, 'A'))[0] || null;

  // DNSSEC
  const dnskey = await records(domain, 'DNSKEY');
  const adResp = await query(domain, 'A');
  const dnssecSigned = dnskey.length > 0 || !!(adResp && adResp.AD);

  // HTTP / HTTPS
  const httpsResp = await httpProbe(`https://${domain}`);
  const httpResp = await httpProbe(`http://${domain}`);

  // ===========================================================================
  // PARENT / DELEGATION
  // ===========================================================================
  if (ns.length) {
    results.push(mk('Parent', 'Delegation (NS records)', 'pass',
      `The zone is delegated to:<br>${ns.map((n) => `${n}${nsIpMap[n] ? ` [${nsIpMap[n]}]` : ''}`).join('<br>')}`));
  } else {
    results.push(mk('Parent', 'Delegation (NS records)', 'fail',
      'No NS records were returned. The domain may not exist or its delegation is broken.'));
  }

  // ===========================================================================
  // NS
  // ===========================================================================
  if (ns.length) {
    results.push(mk('NS', 'NS records', 'pass', `Nameservers:<br>${ns.join('<br>')}`));

    results.push(mk('NS', 'Multiple nameservers', ns.length >= 2 ? 'pass' : 'fail',
      ns.length >= 2
        ? `Good. You have ${ns.length} nameservers. RFC 2182 recommends at least 2.`
        : 'You have only one nameserver. RFC 2182 recommends at least two.'));

    const resolved = Object.keys(nsIpMap).length;
    results.push(mk('NS', 'Nameserver A records', resolved === ns.length ? 'pass' : 'warn',
      resolved === ns.length
        ? 'Good. Every nameserver resolves to an IP address.'
        : `${ns.length - resolved} of ${ns.length} nameservers did not resolve to an A record.`));

    const ips = Object.values(nsIpMap);
    if (ips.length) {
      const subnets = new Set(ips.map((ip) => ip.split('.').slice(0, 3).join('.')));
      results.push(mk('NS', 'Nameservers on different subnets', subnets.size > 1 || ips.length < 2 ? 'pass' : 'warn',
        subnets.size > 1
          ? 'Good. Your nameservers appear to be on different /24 subnets.'
          : 'All nameservers appear to be in the same /24 subnet, reducing redundancy.'));

      const privates = ips.filter(isPrivateIp);
      results.push(mk('NS', 'Nameserver IPs are public', privates.length ? 'fail' : 'pass',
        privates.length ? `Private/reserved IPs found: ${privates.join(', ')}` : 'Good. All nameserver IPs are public.'));
    }

    results.push(mk('NS', 'Wildcard DNS', wildcard ? 'info' : 'pass',
      wildcard
        ? `A random subdomain resolved to ${wildcard}, indicating a wildcard (*) record.`
        : 'Good. No wildcard record detected (a random subdomain did not resolve).'));
  }

  // ===========================================================================
  // SOA
  // ===========================================================================
  if (soaRaw) {
    // "mname rname serial refresh retry expire minimum"
    const p = soaRaw.trim().split(/\s+/);
    const soa = { primary: clean(p[0]), admin: clean(p[1]), serial: p[2], refresh: p[3], retry: p[4], expiration: p[5], minimum: p[6] };

    results.push(mk('SOA', 'SOA record', 'pass',
      `Primary NS (MNAME): ${soa.primary}<br>Hostmaster (RNAME): ${soa.admin}<br>Serial: ${soa.serial}<br>Refresh: ${soa.refresh}<br>Retry: ${soa.retry}<br>Expire: ${soa.expiration}<br>Minimum TTL: ${soa.minimum}`));

    results.push(mk('SOA', 'SOA Serial', /^\d{8,10}$/.test(String(soa.serial)) ? 'pass' : 'info',
      `Serial is ${soa.serial}. Any incrementing integer is valid, but YYYYMMDDnn is recommended.`));
    results.push(mk('SOA', 'SOA Refresh', rangeStatus(soa.refresh, 1200, 43200), rangeInfo('Refresh', soa.refresh, 1200, 43200, 'RFC 1912 recommends 20 min \u2013 12 h.')));
    results.push(mk('SOA', 'SOA Retry', rangeStatus(soa.retry, 180, 7200), rangeInfo('Retry', soa.retry, 180, 7200, 'RFC 1912 recommends 3 min \u2013 2 h.')));
    results.push(mk('SOA', 'SOA Expire', rangeStatus(soa.expiration, 1209600, 2419200), rangeInfo('Expire', soa.expiration, 1209600, 2419200, 'RFC 1912 recommends 2 \u2013 4 weeks.')));
    results.push(mk('SOA', 'SOA Minimum TTL', rangeStatus(soa.minimum, 300, 86400), rangeInfo('Minimum TTL', soa.minimum, 300, 86400, 'Recommended 5 min \u2013 1 day.')));
  } else {
    results.push(mk('SOA', 'SOA record', 'fail', 'No SOA record could be retrieved. Every zone must have exactly one SOA record.'));
  }

  // ===========================================================================
  // MX
  // ===========================================================================
  const mx = mxRaw
    .map((d) => {
      const [pref, ...rest] = d.trim().split(/\s+/);
      return { priority: Number(pref), exchange: clean(rest.join(' ')) };
    })
    .sort((a, b) => a.priority - b.priority);

  if (mx.length) {
    results.push(mk('MX', 'MX records', 'pass',
      `MX records (priority \u2014 host):<br>${mx.map((m) => `${m.priority} \u2014 ${m.exchange}`).join('<br>')}`));

    const ipMx = mx.filter((m) => /^\d{1,3}(\.\d{1,3}){3}$/.test(m.exchange));
    results.push(mk('MX', 'MX is a hostname, not an IP', ipMx.length ? 'fail' : 'pass',
      ipMx.length ? `MX must point to a hostname. Offending: ${ipMx.map((m) => m.exchange).join(', ')}` : 'Good. All MX records point to hostnames.'));

    const dupes = mx.map((m) => m.exchange).filter((v, i, a) => a.indexOf(v) !== i);
    results.push(mk('MX', 'Duplicate MX records', dupes.length ? 'warn' : 'pass',
      dupes.length ? `Duplicate MX hosts: ${[...new Set(dupes)].join(', ')}` : 'Good. No duplicate MX records.'));

    const noA = [];
    for (const m of mx) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(m.exchange)) continue;
      if (!(await records(m.exchange, 'A')).length && !(await records(m.exchange, 'AAAA')).length) noA.push(m.exchange);
    }
    results.push(mk('MX', 'MX records resolve to addresses', noA.length ? 'fail' : 'pass',
      noA.length ? `These MX hosts did not resolve: ${noA.join(', ')}` : 'Good. Every MX host resolves to an address.'));
  } else {
    results.push(mk('MX', 'MX records', 'warn', 'No MX records were found. This domain cannot receive email via standard MX delivery.'));
  }

  // ===========================================================================
  // MAIL
  // ===========================================================================
  results.push(mk('Mail', 'SPF record', spf ? 'pass' : 'warn',
    spf ? `SPF record found:<br><code>${esc(spf)}</code>` : 'No SPF (v=spf1) TXT record found. SPF helps prevent sender spoofing.'));

  if (spfRecords.length > 1) {
    results.push(mk('Mail', 'Single SPF record', 'fail',
      `Found ${spfRecords.length} SPF records. RFC 7208 permits only one; multiple records make SPF fail permanently.`));
  }
  if (spf) {
    const q = (spf.match(/([~\-+?])all\b/i) || [])[1] || null;
    results.push(mk('Mail', 'SPF policy (all mechanism)',
      q === '-' || q === '~' ? 'pass' : q === '?' ? 'warn' : q === '+' ? 'fail' : 'warn',
      q === '-' ? 'Good. SPF ends with -all (hard fail).'
        : q === '~' ? 'SPF ends with ~all (soft fail). Acceptable; -all is stricter.'
        : q === '?' ? 'SPF ends with ?all (neutral), which provides no protection.'
        : q === '+' ? 'SPF ends with +all, which lets anyone send as your domain. Remove this immediately.'
        : 'SPF has no explicit all mechanism. Add -all or ~all.'));
  }

  results.push(mk('Mail', 'DKIM record', dkim.length ? 'pass' : 'info',
    dkim.length ? `DKIM keys found for selector(s): ${dkim.join(', ')}.` : 'No DKIM key found for common selectors (a custom selector may still exist).'));

  results.push(mk('Mail', 'DMARC record', dmarc ? 'pass' : 'info',
    dmarc ? `DMARC record found:<br><code>${esc(dmarc)}</code>` : `No DMARC record at _dmarc.${domain}. DMARC builds on SPF/DKIM.`));

  results.push(mk('Mail', 'MTA-STS', mtaSts ? 'pass' : 'info',
    mtaSts ? `MTA-STS policy record found:<br><code>${esc(mtaSts)}</code>` : `No _mta-sts.${domain} record. MTA-STS enforces TLS for inbound mail.`));

  results.push(mk('Mail', 'TLS-RPT', tlsRpt ? 'pass' : 'info',
    tlsRpt ? `SMTP TLS reporting is configured:<br><code>${esc(tlsRpt)}</code>` : `No _smtp._tls.${domain} record. TLS-RPT reports mail TLS failures.`));

  results.push(mk('Mail', 'BIMI', bimi ? 'pass' : 'info',
    bimi ? `BIMI record found:<br><code>${esc(bimi)}</code>` : `No default._bimi.${domain} record. BIMI shows your brand logo in supporting inboxes.`));

  // ===========================================================================
  // WEB
  // ===========================================================================
  results.push(mk('Web', 'WWW record', wwwA.length ? 'pass' : (wwwCname ? 'info' : 'warn'),
    wwwA.length ? `www.${domain} resolves to: ${wwwA.join(', ')}` : wwwCname ? `www.${domain} is a CNAME to ${wwwCname}.` : `No A or CNAME record found for www.${domain}.`));

  results.push(mk('Web', 'Apex A record', apexA.length ? 'pass' : 'info',
    apexA.length ? `${domain} resolves to: ${apexA.join(', ')}` : `No A record found for the apex ${domain}.`));

  const anyAAAA = apexAAAA.length || wwwAAAA.length;
  results.push(mk('Web', 'IPv6 (AAAA) records', anyAAAA ? 'pass' : 'info',
    anyAAAA
      ? `IPv6 is available:${apexAAAA.length ? `<br>${domain}: ${apexAAAA.join(', ')}` : ''}${wwwAAAA.length ? `<br>www.${domain}: ${wwwAAAA.join(', ')}` : ''}`
      : `No AAAA records found for ${domain} or www.${domain}.`));

  if (!httpsResp.error) {
    results.push(mk('Web', 'HTTPS reachable', httpsResp.status < 500 ? 'pass' : 'warn',
      `https://${domain} responded with HTTP ${httpsResp.status}.`));
  } else {
    results.push(mk('Web', 'HTTPS reachable', 'warn', `Could not complete an HTTPS request to ${domain} (${esc(httpsResp.error)}).`));
  }

  if (!httpResp.error) {
    const loc = httpResp.location || '';
    const redir = httpResp.status >= 300 && httpResp.status < 400 && /^https:/i.test(loc);
    results.push(mk('Web', 'HTTP to HTTPS redirect', redir ? 'pass' : 'warn',
      redir ? `Good. http://${domain} redirects (HTTP ${httpResp.status}) to ${esc(loc)}.` : `http://${domain} did not redirect to HTTPS (HTTP ${httpResp.status}).`));
  }

  // ===========================================================================
  // SSL (edge: handshake + transport headers)
  // ===========================================================================
  if (!httpsResp.error) {
    results.push(mk('SSL', 'TLS handshake', 'pass', `A TLS connection to https://${domain} completed successfully.`));
    const hsts = httpsResp.headers.get('strict-transport-security');
    results.push(mk('SSL', 'HSTS header', hsts ? 'pass' : 'info',
      hsts ? `Strict-Transport-Security is set:<br><code>${esc(hsts)}</code>` : 'No HSTS header. HSTS forces browsers to use HTTPS.'));
  } else {
    results.push(mk('SSL', 'TLS handshake', 'fail',
      `The TLS handshake with ${domain} failed (${esc(httpsResp.error)}). The certificate may be invalid, expired, or the host may not serve HTTPS.`));
  }

  // ===========================================================================
  // SECURITY
  // ===========================================================================
  results.push(mk('Security', 'CAA record', caa.length ? 'pass' : 'info',
    caa.length
      ? `CAA records restrict which CAs may issue certificates:<br>${caa.map((c) => esc(unquoteTxt(c))).join('<br>')}`
      : 'No CAA record found. Any Certificate Authority may issue certificates for this domain.'));

  results.push(mk('Security', 'DNSSEC', dnssecSigned ? 'pass' : 'info',
    dnssecSigned
      ? 'Good. The zone is DNSSEC-signed (DNSKEY present / answers authenticated).'
      : 'The zone does not appear to use DNSSEC, which protects against DNS spoofing.'));

  const summary = results.reduce((acc, r) => ((acc[r.status] = (acc[r.status] || 0) + 1), acc), {});
  return { domain, results, summary };
}
