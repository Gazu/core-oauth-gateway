import type { NextRequest } from "next/server";
import { authorizationController } from "@/oauth/interfaces/http/controllers/authorization.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET(request: NextRequest): Promise<Response> {
  return authorizationController.authorize(request);
}
