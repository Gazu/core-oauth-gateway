import type { NextRequest } from "next/server";
import { tokenResourceController } from "@/oauth/interfaces/http/controllers/token-resource.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function POST(request: NextRequest): Promise<Response> {
  return tokenResourceController.revokeById(request);
}
