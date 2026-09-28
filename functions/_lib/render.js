// Pure HTML rendering for the DNS report — runs on the Cloudflare Workers runtime.

export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export const STATUS_META = {
  pass: { label: 'Pass', badge: 'bg-emerald-500', text: 'text-emerald-600 dark:text-emerald-400', icon: '&#10003;', hex: '#10b981' },
  info: { label: 'Info', badge: 'bg-sky-500', text: 'text-sky-600 dark:text-sky-400', icon: 'i', hex: '#0ea5e9' },
  warn: { label: 'Warning', badge: 'bg-amber-500', text: 'text-amber-600 dark:text-amber-400', icon: '&#33;', hex: '#f59e0b' },
  fail: { label: 'Error', badge: 'bg-rose-500', text: 'text-rose-600 dark:text-rose-400', icon: '&#10007;', hex: '#f43f5e' }
};

export const PLURAL = { pass: 'Passed', info: 'Info', warn: 'Warnings', fail: 'Errors' };

export const CATEGORY_ORDER = ['Parent', 'NS', 'SOA', 'MX', 'Mail', 'Web', 'SSL', 'Security'];

export const CATEGORY_DESC = {
  Parent: 'Delegation reported by the resolver',
  NS: 'Authoritative nameservers for the zone',
  SOA: 'Start of Authority record and its timers',
  MX: 'Mail exchanger records',
  Mail: 'SPF, DKIM, DMARC and mail policy',
  Web: 'Web server, HTTPS and redirects',
  SSL: 'HTTPS handshake and transport security',
  Security: 'CAA and DNSSEC protections'
};

const CATEGORY_ICON = {
  Parent: { color: 'indigo', anim: 'anim-pulse', path: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v3M12 10l-6 7M12 10l6 7"/>' },
  NS: { color: 'violet', anim: 'anim-pulse', path: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>' },
  SOA: { color: 'amber', anim: 'anim-swing', path: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>' },
  MX: { color: 'sky', anim: 'anim-pulse', path: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"/>' },
  Mail: { color: 'rose', anim: 'anim-bob', path: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>' },
  Web: { color: 'emerald', anim: 'anim-spin', path: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
  SSL: { color: 'teal', anim: 'anim-bob', path: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
  Security: { color: 'fuchsia', anim: 'anim-pulse', path: '<path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z"/><path d="m9 12 2 2 4-4"/>' }
};

function renderRow(r) {
  const m = STATUS_META[r.status] || STATUS_META.info;
  return `
    <tr class="border-t border-slate-100 dark:border-slate-800">
      <td class="py-3 pl-4 pr-2 align-top w-28">
        <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold text-white ${m.badge}">
          <span aria-hidden="true">${m.icon}</span>${m.label}
        </span>
      </td>
      <td class="py-3 px-2 align-top font-medium text-slate-800 dark:text-slate-100 w-64">${escapeHtml(r.test)}</td>
      <td class="py-3 pr-4 pl-2 align-top text-sm text-slate-600 dark:text-slate-300 leading-relaxed">${r.info}</td>
    </tr>`;
}

function renderCategory(cat, rows, index = 0) {
  const counts = rows.reduce((a, r) => ((a[r.status] = (a[r.status] || 0) + 1), a), {});
  const chips = Object.entries(counts)
    .map(([s, n]) => {
      const m = STATUS_META[s];
      return `<span class="inline-flex items-center gap-1 text-xs font-medium ${m.text}"><span class="h-2 w-2 rounded-full ${m.badge}"></span>${n}</span>`;
    })
    .join('');
  const ic = CATEGORY_ICON[cat] || CATEGORY_ICON.Web;
  return `
    <section class="reveal overflow-hidden rounded-2xl border border-slate-200/80 bg-white/70 shadow-sm backdrop-blur transition hover:shadow-md dark:border-slate-800/80 dark:bg-slate-900/60" style="animation-delay:${index * 70}ms">
      <button type="button" data-accordion-toggle aria-expanded="true"
        class="flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left transition hover:bg-slate-50/60 dark:hover:bg-slate-800/30">
        <span class="flex items-center gap-3">
          <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-${ic.color}-500/10 text-${ic.color}-600 dark:text-${ic.color}-400">
            <svg class="h-5 w-5 ${ic.anim}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ic.path}</svg>
          </span>
          <span>
            <span class="block text-sm font-semibold tracking-tight text-slate-900 dark:text-white">${cat}</span>
            <span class="block text-xs text-slate-500 dark:text-slate-400">${CATEGORY_DESC[cat] || ''}</span>
          </span>
        </span>
        <span class="flex items-center gap-3">
          <span class="hidden items-center gap-3 sm:flex">${chips}</span>
          <svg class="chevron h-4 w-4 text-slate-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
        </span>
      </button>
      <div class="accordion-body border-t border-slate-200/70 dark:border-slate-800/70">
        <div class="accordion-inner">
          <div class="overflow-x-auto">
            <table class="w-full border-collapse text-left">
              <tbody>${rows.map(renderRow).join('')}</tbody>
            </table>
          </div>
        </div>
      </div>
    </section>`;
}

export function renderReport({ domain, results, summary }) {
  const grouped = {};
  for (const r of results) (grouped[r.category] ||= []).push(r);

  const summaryChips = Object.entries(summary)
    .sort((a, b) => CATEGORY_ORDER.indexOf(a[0]) - CATEGORY_ORDER.indexOf(b[0]))
    .map(([s, n]) => {
      const m = STATUS_META[s] || STATUS_META.info;
      const plural = n === 1 ? m.label : PLURAL[s] || `${m.label}s`;
      return `<span class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 shadow-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
        <span class="h-2.5 w-2.5 rounded-full ${m.badge}"></span>${n} ${plural}
      </span>`;
    })
    .join('');

  const sections = CATEGORY_ORDER.filter((c) => grouped[c])
    .map((c, i) => renderCategory(c, grouped[c], i))
    .join('');

  return `
    <div class="reveal space-y-5">
      <div class="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-200/80 bg-white/70 p-5 shadow-sm backdrop-blur dark:border-slate-800/80 dark:bg-slate-900/60">
        <div class="flex items-center gap-3">
          <span class="relative flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
            <svg xmlns="http://www.w3.org/2000/svg" class="absolute h-6 w-6 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <img data-favicon src="https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(domain)}" alt="" width="28" height="28" loading="lazy" class="relative h-7 w-7 rounded" onerror="this.remove()" />
          </span>
          <div>
            <p class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Report for</p>
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white">${escapeHtml(domain)}</h2>
          </div>
        </div>
        <div class="flex flex-1 flex-wrap items-center justify-end gap-2">
          ${summaryChips}
          <button type="button" data-download-pdf data-domain="${escapeHtml(domain)}"
             class="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-700 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-200">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download PDF
          </button>
        </div>
      </div>
      ${sections}
    </div>`;
}

export function renderError(message) {
  return `
    <div class="rounded-xl border border-rose-200 bg-rose-50 p-4 text-rose-700 dark:border-rose-900/50 dark:bg-rose-950/40 dark:text-rose-300">
      <p class="font-semibold">Could not run the report</p>
      <p class="mt-1 text-sm">${escapeHtml(message)}</p>
    </div>`;
}
