import { withOAuthRequestLogging } from "../../../../../src/oauth/logger";
import { pushedAuthorizeHandler } from "../../../../../src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = withOAuthRequestLogging("POST pushedAuthorizeHandler", pushedAuthorizeHandler);
