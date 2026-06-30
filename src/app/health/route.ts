import type { NextRequest } from "next/server";
import { healthController } from "@/oauth/interfaces/http/controllers/health.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET(request: NextRequest): Promise<Response> {
  return healthController.get(request);
}
