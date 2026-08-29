// Shared validation/reply helpers for the public contact/waitlist Pages Functions
// (apps/aether-ra, castrum-maris, finca-madre, promontory-plover, tinytars).

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email) && email.length <= 254;
}

// Honeypot field real visitors leave empty; a filled one flags a bot submission.
export function isHoneypotFilled(body: Record<string, unknown>, field = "company"): boolean {
  return typeof body[field] === "string" && body[field].trim() !== "";
}

export function jsonResponse(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
