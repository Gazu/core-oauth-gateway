import { withOAuthRequestLogging } from "../../../../src/oauth/logger";
import { introspectionHandler } from "../../../../src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = withOAuthRequestLogging("POST introspectionHandler", introspectionHandler);
