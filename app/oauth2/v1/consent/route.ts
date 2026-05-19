import { withOAuthRequestLogging } from "@/src/oauth/logger";
import { consentHandler } from "@/src/oauth/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withOAuthRequestLogging("GET consentHandler", consentHandler);
