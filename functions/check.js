import { runChecks } from './_lib/checks.js';
import { renderReport, renderError } from './_lib/render.js';

// POST /check -> HTML report fragment (HTMX target).
export async function onRequestPost({ request }) {
  const headers = { 'content-type': 'text/html; charset=utf-8' };
  try {
    const form = await request.formData();
    const report = await runChecks(form.get('domain'));
    return new Response(renderReport(report), { headers });
  } catch (err) {
    return new Response(renderError(err.message || 'Unexpected error'), { headers });
  }
}
