import { withOAuthRequestLogging } from "../../../../src/oauth/logger";
import { userInfoHandler } from "../../../../src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withOAuthRequestLogging("GET userInfoHandler", userInfoHandler);
export const POST = withOAuthRequestLogging("POST userInfoHandler", userInfoHandler);
