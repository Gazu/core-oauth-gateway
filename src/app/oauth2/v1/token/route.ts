import type { NextRequest } from "next/server";
import { tokenController } from "@/oauth/interfaces/http/controllers/token.controller";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function POST(request: NextRequest): Promise<Response> {
  return tokenController.issue(request);
}
