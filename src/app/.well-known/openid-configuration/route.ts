import type { NextRequest } from "next/server";
import { discoveryController } from "@/oauth/interfaces/http/controllers/discovery.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET(request: NextRequest): Promise<Response> {
  return discoveryController.configuration(request);
}
