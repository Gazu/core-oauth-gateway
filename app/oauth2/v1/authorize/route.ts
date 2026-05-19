import { withOAuthRequestLogging } from "../../../../src/oauth/logger";
import { authorizeHandler } from "../../../../src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withOAuthRequestLogging("GET authorizeHandler", authorizeHandler);
