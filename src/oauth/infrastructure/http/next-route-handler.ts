import type { NextRequest } from "next/server";
import { withOAuthRequestLogging } from "@/oauth/logger";

type RouteOperation = () => Promise<Response>;

export function handleNextRequest(
  request: NextRequest,
  handlerName: string,
  operation: RouteOperation
): Promise<Response> {
  const route = withOAuthRequestLogging(handlerName, operation);
  return route(request);
}
