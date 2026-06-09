import { withOAuthRequestLogging } from "../../src/oauth/logger";
import { healthHandler } from "../../src/oauth/health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withOAuthRequestLogging("GET healthHandler", healthHandler);
