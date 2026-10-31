/**
 * Contact form endpoint for agenticintegrationhub.com (Cloudflare Pages Function).
 * POST /api/contact  →  verifies Cloudflare Turnstile, validates input, sends one email via Resend.
 *
 * Environment variables (Cloudflare Pages → Settings → Variables and Secrets; mark keys as "Secret"):
 *   RESEND_API_KEY        Resend API key (secret, never committed)
 *   TURNSTILE_SECRET_KEY  Cloudflare Turnstile secret key (secret)
 *   CONTACT_TO            Destination inbox, e.g. contact@agenticintegrationhub.com
 *   CONTACT_FROM          Verified sender, e.g. "Agentic Integration Hub <form@agenticintegrationhub.com>"
 */

const ALLOWED_ORIGINS = ["https://agenticintegrationhub.com", "https://www.agenticintegrationhub.com"];
const LIMITS = { name: 100, email: 254, subject: 150, message: 5000 };
const EMAIL_RE = /^[^\s@<>()",;:]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });

// Strip control characters; collapse line breaks in single-line fields (prevents header injection).
const clean = (v, max, singleLine) => {
  let s = typeof v === "string" ? v : "";
  s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  if (singleLine) s = s.replace(/[\r\n]+/g, " ");
  return s.trim().slice(0, max);
};

const isAllowedOrigin = (origin) =>
  ALLOWED_ORIGINS.includes(origin) || /^https:\/\/[a-z0-9-]+\.agentic-integration-hub\.pages\.dev$/.test(origin || "");

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin");
  if (!isAllowedOrigin(origin)) return json(403, { ok: false, error: "Forbidden." });
  if (!(request.headers.get("Content-Type") || "").includes("application/json")) return json(415, { ok: false, error: "Unsupported request." });
  if (Number(request.headers.get("Content-Length") || 0) > 20000) return json(413, { ok: false, error: "Message is too long." });
  if (!env.RESEND_API_KEY || !env.CONTACT_TO || !env.CONTACT_FROM || !env.TURNSTILE_SECRET_KEY)
    return json(503, { ok: false, error: "The contact form is not configured yet. Please email us instead." });

  let data;
  try { data = await request.json(); } catch { return json(400, { ok: false, error: "Invalid request." }); }

  // Honeypot: real visitors never fill this hidden field. Pretend success so bots learn nothing.
  if (clean(data.website, 200, true)) return json(200, { ok: true });

  const name = clean(data.name, LIMITS.name, true);
  const email = clean(data.email, LIMITS.email, true);
  const subject = clean(data.subject, LIMITS.subject, true);
  const message = clean(data.message, LIMITS.message, false);
  if (!EMAIL_RE.test(email)) return json(400, { ok: false, error: "Please enter a valid email address." });
  if (subject.length < 3) return json(400, { ok: false, error: "Please enter a subject." });
  if (message.length < 10) return json(400, { ok: false, error: "Please enter a message of at least 10 characters." });

  // Verify Cloudflare Turnstile (bot protection) on the server.
  const token = clean(data.turnstileToken, 2048, true);
  if (!token) return json(400, { ok: false, error: "Please complete the verification check." });
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY);
  form.append("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.append("remoteip", ip);
  const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form })
    .then((r) => r.json()).catch(() => ({ success: false }));
  if (!verify.success) return json(403, { ok: false, error: "Verification failed. Please try again." });

  // Send. The visitor's address goes in Reply-To only; the sender is always your verified domain (no spoofing).
  const text = [
    "New message from the Agentic Integration Hub contact form",
    "",
    `Name:    ${name || "(not given)"}`,
    `Email:   ${email}`,
    `Subject: ${subject}`,
    "",
    message,
    "",
    "---",
    `Sent ${new Date().toISOString()} via agenticintegrationhub.com/contact`,
  ].join("\n");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: env.CONTACT_FROM,
      to: [env.CONTACT_TO],
      reply_to: email,
      subject: `[Website] ${subject}`,
      text,
    }),
  }).catch(() => null);

  if (!res || !res.ok) return json(502, { ok: false, error: "Your message could not be sent right now. Please email us instead." });
  return json(200, { ok: true });
}

// Any other method on this path is rejected.
export async function onRequest() {
  return json(405, { ok: false, error: "Method not allowed." });
}
