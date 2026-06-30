import type { NextRequest } from "next/server";

export function validateRouteMethod(
  request: NextRequest,
  allowedMethods: readonly string[]
): Response | null {
  if (allowedMethods.includes(request.method)) return null;

  return new Response(null, {
    status: 405,
    headers: {
      Allow: allowedMethods.join(", ")
    }
  });
}
