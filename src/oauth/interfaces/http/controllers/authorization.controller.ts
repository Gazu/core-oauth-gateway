import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";
import {
  formRequest,
  jsonRequest,
  queryRequest
} from "@/oauth/interfaces/http/validators/oauth-request.mapper";

export const authorizationController = {
  authorize(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET authorizeHandler", allowedMethods: ["GET"] },
      () => getContainer().authorize.execute(queryRequest(request))
    );
  },

  pushedAuthorize(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "POST pushedAuthorizeHandler", allowedMethods: ["POST"] },
      async () => getContainer().pushedAuthorize.execute(await formRequest(request))
    );
  },

  consent(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET consentHandler", allowedMethods: ["GET"] },
      () => getContainer().getConsent.execute(queryRequest(request).parameters)
    );
  },

  authDetails(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "POST authDetailsHandler", allowedMethods: ["POST"] },
      async () => {
        const dto = await jsonRequest<{ oauth_key?: string; auth_jwt?: string }>(request);
        return getContainer().getAuthDetails.execute(dto.body ?? null);
      }
    );
  },

  userAuthorize(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "POST userAuthorizeHandler", allowedMethods: ["POST"] },
      async () => {
        const dto = await jsonRequest<{ oauth_key?: string; user_jwt?: string }>(request);
        return getContainer().completeUserAuthorization.execute(dto);
      }
    );
  },

  userError(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "POST userErrorHandler", allowedMethods: ["POST"] },
      async () => {
        const dto = await jsonRequest<{ oauth_key?: string; error_jwt?: string }>(request);
        return getContainer().handleUserError.execute(dto);
      }
    );
  }
};
