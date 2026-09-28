// Vector PDF generation with pdf-lib — Workers-compatible, full pagination control.
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { CATEGORY_ORDER, CATEGORY_DESC } from './render.js';

const PW = 595.28;
const PH = 841.89;
const L = 50;
const R = 545;
const CW = R - L;

const C = {
  pass: rgb(0.063, 0.725, 0.506),
  info: rgb(0.055, 0.647, 0.914),
  warn: rgb(0.961, 0.62, 0.043),
  fail: rgb(0.957, 0.247, 0.369),
  indigo: rgb(0.388, 0.4, 0.945),
  dark: rgb(0.059, 0.09, 0.165),
  body: rgb(0.28, 0.33, 0.41),
  muted: rgb(0.392, 0.455, 0.545),
  line: rgb(0.886, 0.91, 0.941),
  headbg: rgb(0.933, 0.949, 0.969),
  panel: rgb(0.973, 0.98, 0.988),
  white: rgb(1, 1, 1)
};

const STAT = {
  pass: { label: 'PASS', c: C.pass },
  info: { label: 'INFO', c: C.info },
  warn: { label: 'WARN', c: C.warn },
  fail: { label: 'FAIL', c: C.fail }
};

// Strip the limited report HTML to ASCII-safe plain text (WinAnsi-encodable).
function toText(html) {
  return String(html)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li)>/gi, '\n')
    .replace(/<li>/gi, '- ')
    .replace(/<[^>]+>/g, '')
    .replace(/&mdash;/g, '-')
    .replace(/&rarr;/g, '->')
    .replace(/&middot;/g, '-')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#10003;/g, '')
    .replace(/&#10007;/g, '')
    .replace(/&#33;/g, '!')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2022\u00b7]/g, '-')
    .replace(/[ \t]+/g, ' ')
    .replace(/[^\x20-\x7E\n]/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function wrap(text, font, size, maxW) {
  const out = [];
  for (const para of String(text).split('\n')) {
    if (para === '') { out.push(''); continue; }
    let line = '';
    for (const word of para.split(' ')) {
      const test = line ? line + ' ' + word : word;
      if (font.widthOfTextAtSize(test, size) <= maxW) {
        line = test;
      } else {
        if (line) out.push(line);
        if (font.widthOfTextAtSize(word, size) > maxW) {
          let chunk = '';
          for (const ch of word) {
            if (font.widthOfTextAtSize(chunk + ch, size) <= maxW) chunk += ch;
            else { out.push(chunk); chunk = ch; }
          }
          line = chunk;
        } else {
          line = word;
        }
      }
    }
    if (line) out.push(line);
  }
  return out.length ? out : [''];
}

export async function buildPdf(report) {
  const doc = await PDFDocument.create();
  doc.setTitle(`DNS Report - ${report.domain}`);
  doc.setAuthor('DNS Checker');
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const fontB = await doc.embedFont(StandardFonts.HelveticaBold);

  // Coordinate helpers (top-left origin abstraction over pdf-lib's bottom-left).
  const text = (page, s, xTop, yTop, { size = 9, f = font, color = C.dark, align, boxW } = {}) => {
    let x = xTop;
    const w = f.widthOfTextAtSize(s, size);
    if (align === 'center' && boxW) x = xTop + (boxW - w) / 2;
    else if (align === 'right' && boxW) x = xTop + (boxW - w);
    page.drawText(s, { x, y: PH - yTop - size, size, font: f, color });
  };
  const rect = (page, xTop, yTop, w, h, { color, border, borderW = 0 } = {}) =>
    page.drawRectangle({ x: xTop, y: PH - yTop - h, width: w, height: h, color, borderColor: border, borderWidth: borderW });
  const hline = (page, x1, yTop, x2, { color = C.line, w = 0.7 } = {}) =>
    page.drawLine({ start: { x: x1, y: PH - yTop }, end: { x: x2, y: PH - yTop }, thickness: w, color });

  const grouped = {};
  for (const r of report.results) (grouped[r.category] ||= []).push(r);
  const cats = CATEGORY_ORDER.filter((c) => grouped[c]);

  drawCover(doc, report, { text, rect }, font, fontB);

  let page = doc.addPage([PW, PH]);
  const contentPages = [page];
  let y = 82;
  const bottom = 777;
  const ensure = (need) => {
    if (y + need > bottom) {
      page = doc.addPage([PW, PH]);
      contentPages.push(page);
      y = 82;
    }
  };

  const testX = L + 66;
  const testW = 148;
  const infoX = L + 66 + 158;
  const infoW = R - infoX;

  for (const cat of cats) {
    ensure(40 + 32);
    rect(page, L, y, CW, 30, { color: C.headbg });
    text(page, cat, L + 12, y + 8, { size: 12, f: fontB, color: C.dark });
    text(page, CATEGORY_DESC[cat] || '', L + 12, y + 20, { size: 8, color: C.muted });
    y += 40;

    for (const r of grouped[cat]) {
      const st = STAT[r.status] || STAT.info;
      const testLines = wrap(r.test, fontB, 9, testW);
      const infoLines = wrap(toText(r.info), font, 8.5, infoW);
      const rowH = Math.max(testLines.length * 11, infoLines.length * 11.5, 16) + 12;
      ensure(rowH);
      hline(page, L, y, R, { color: C.line, w: 0.5 });
      const rowY = y + 9;

      rect(page, L, rowY, 50, 15, { color: st.c });
      text(page, st.label, L, rowY + 4.5, { size: 7.5, f: fontB, color: C.white, align: 'center', boxW: 50 });

      let ty = rowY;
      for (const ln of testLines) { text(page, ln, testX, ty, { size: 9, f: fontB, color: C.dark }); ty += 11; }
      let iy = rowY;
      for (const ln of infoLines) { text(page, ln, infoX, iy, { size: 8.5, color: C.body }); iy += 11.5; }

      y += rowH;
    }
    y += 8;
  }

  // Running header + footer on every content page.
  const total = contentPages.length;
  contentPages.forEach((pg, idx) => {
    text(pg, 'DNS Report', L, 34, { size: 10, f: fontB, color: C.indigo });
    text(pg, report.domain, L, 34, { size: 9, color: C.muted, align: 'right', boxW: CW });
    hline(pg, L, 54, R);
    hline(pg, L, PH - 44, R);
    text(pg, 'DNS Checker - Real-time DNS, mail & security diagnostics', L, PH - 38, { size: 8, color: C.muted });
    text(pg, `Page ${idx + 1} of ${total}`, L, PH - 38, { size: 8, color: C.muted, align: 'right', boxW: CW });
  });

  return doc.save();
}

function drawCover(doc, report, { text, rect }, font, fontB) {
  const page = doc.addPage([PW, PH]);

  rect(page, 0, 0, PW, 210, { color: C.indigo });

  // Globe glyph
  const cx = 90;
  const cyTop = 92;
  const cy = PH - cyTop;
  page.drawCircle({ x: cx, y: cy, size: 26, borderColor: C.white, borderWidth: 1.6 });
  page.drawLine({ start: { x: cx - 26, y: cy }, end: { x: cx + 26, y: cy }, thickness: 1.6, color: C.white });
  page.drawEllipse({ x: cx, y: cy, xScale: 12, yScale: 26, borderColor: C.white, borderWidth: 1.6 });
  page.drawLine({ start: { x: cx, y: cy + 26 }, end: { x: cx, y: cy - 26 }, thickness: 1.6, color: C.white });

  text(page, 'DNS Health Report', 132, 66, { size: 26, f: fontB, color: C.white });
  text(page, 'Comprehensive DNS, mail & security analysis', 132, 102, { size: 11, color: rgb(0.88, 0.9, 0.99) });

  text(page, report.domain, L, 250, { size: 22, f: fontB, color: C.dark });
  const gen = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  text(page, 'Generated ' + gen, L, 282, { size: 10, color: C.muted });

  const order = ['pass', 'info', 'warn', 'fail'];
  const labels = { pass: 'Passed', info: 'Info', warn: 'Warnings', fail: 'Errors' };
  const gap = 14;
  const bw = (CW - gap * 3) / 4;
  const by = 322;
  const bh = 78;
  order.forEach((k, i) => {
    const bx = L + i * (bw + gap);
    rect(page, bx, by, bw, bh, { color: C.white, border: C.line, borderW: 1 });
    rect(page, bx + 12, by + 14, 4, bh - 28, { color: STAT[k].c });
    text(page, String(report.summary[k] || 0), bx, by + 18, { size: 26, f: fontB, color: STAT[k].c, align: 'center', boxW: bw });
    text(page, labels[k], bx, by + 56, { size: 10, color: C.muted, align: 'center', boxW: bw });
  });

  const fail = report.summary.fail || 0;
  const warn = report.summary.warn || 0;
  const status = fail ? { t: 'Issues found', c: C.fail } : warn ? { t: 'Needs attention', c: C.warn } : { t: 'Healthy', c: C.pass };
  const sy = 440;
  rect(page, L, sy, CW, 54, { color: C.panel, border: C.line, borderW: 1 });
  page.drawCircle({ x: L + 28, y: PH - (sy + 27), size: 7, color: status.c });
  text(page, 'Overall status: ' + status.t, L + 46, sy + 12, { size: 13, f: fontB, color: C.dark });
  const catCount = new Set(report.results.map((r) => r.category)).size;
  text(page, `${report.results.length} checks performed across ${catCount} categories.`, L + 46, sy + 31, { size: 9, color: C.muted });

  text(page, 'DNS Checker - Real-time DNS, mail & security diagnostics - Results reflect live lookups', L, PH - 58, { size: 8, color: C.muted, align: 'center', boxW: CW });
}
