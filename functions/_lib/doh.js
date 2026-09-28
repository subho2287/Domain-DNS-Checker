// DNS-over-HTTPS client (Cloudflare 1.1.1.1 JSON API) — Workers-compatible.

const DOH_URL = 'https://cloudflare-dns.com/dns-query';

/** Query a record type; returns the parsed JSON response ({ Status, AD, Answer, Authority }). */
export async function doh(name, type) {
  const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(`DoH ${type} ${name} failed (${res.status})`);
  return res.json();
}

const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257, DNSKEY: 48 };

/** Return the `data` strings for answers of a given type. */
export async function records(name, type) {
  try {
    const json = await doh(name, type);
    const want = TYPE_NUM[type];
    return (json.Answer || []).filter((a) => a.type === want).map((a) => a.data);
  } catch {
    return [];
  }
}

/** TXT records with quoting/chunking normalised into plain strings. */
export async function txt(name) {
  return (await records(name, 'TXT')).map(unquoteTxt);
}

export function unquoteTxt(data) {
  // DoH returns TXT as one or more quoted chunks: "chunk1" "chunk2"
  return String(data)
    .replace(/^"(.*)"$/s, '$1')
    .replace(/"\s+"/g, '');
}

/** Whole DoH response including the AD (authenticated-data / DNSSEC) flag. */
export async function query(name, type) {
  try {
    return await doh(name, type);
  } catch {
    return null;
  }
}
