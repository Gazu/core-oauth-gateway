import { withOAuthRequestLogging } from "../../../../src/oauth/logger";
import { tokenHandler } from "../../../../src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = withOAuthRequestLogging("POST tokenHandler", tokenHandler);
