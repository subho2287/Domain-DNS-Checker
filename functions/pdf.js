import { runChecks } from './_lib/checks.js';
import { buildPdf } from './_lib/pdf.js';

// GET /pdf?domain=example.com -> generated PDF report (attachment).
export async function onRequestGet({ request }) {
  const domain = new URL(request.url).searchParams.get('domain') || '';
  try {
    const report = await runChecks(domain);
    const bytes = await buildPdf(report);
    const safe = report.domain.replace(/[^a-z0-9.-]/gi, '_');
    return new Response(bytes, {
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': `attachment; filename="dns-report-${safe}.pdf"`,
        'cache-control': 'no-store'
      }
    });
  } catch (err) {
    return new Response('Could not generate PDF: ' + (err.message || 'error'), { status: 400 });
  }
}
