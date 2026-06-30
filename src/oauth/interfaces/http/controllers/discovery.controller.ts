import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";
import { queryRequest } from "@/oauth/interfaces/http/validators/oauth-request.mapper";

export const discoveryController = {
  configuration(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET openIdConfigurationHandler", allowedMethods: ["GET"] },
      () => getContainer().getDiscoveryDocument.execute(queryRequest(request).baseUrl)
    );
  },

  certs(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET certsHandler", allowedMethods: ["GET"] },
      () => getContainer().getSigningCertificates.execute()
    );
  }
};
