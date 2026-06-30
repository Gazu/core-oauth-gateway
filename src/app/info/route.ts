import type { NextRequest } from "next/server";
import { infoController } from "@/oauth/interfaces/http/controllers/info.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET(request: NextRequest): Promise<Response> {
  return infoController.get(request);
}
