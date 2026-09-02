/**
 * @param {Request} request
 * @param {string | undefined} expectedToken
 */
export function isAuthorized(request, expectedToken) {
  if (!expectedToken) return false;
  return request.headers.get("authorization") === `Bearer ${expectedToken}`;
}

/**
 * @param {unknown} value
 * @param {number} [status]
 */
export function json(value, status = 200) {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

/** @param {unknown} error */
export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
