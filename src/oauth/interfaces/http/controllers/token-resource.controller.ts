import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";
import {
  formRequest,
  userInfoRequest
} from "@/oauth/interfaces/http/validators/oauth-request.mapper";

export const tokenResourceController = {
  tokenInfo(request: NextRequest): Promise<Response> {
    return post(request, "POST tokenInfoHandler", async () =>
      getContainer().getTokenInfo.execute((await formRequest(request)).parameters)
    );
  },

  introspect(request: NextRequest): Promise<Response> {
    return post(request, "POST introspectionHandler", async () =>
      getContainer().introspectToken.execute((await formRequest(request)).parameters)
    );
  },

  userInfo(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: `${request.method} userInfoHandler`, allowedMethods: ["GET", "POST"] },
      async () => getContainer().getUserInfo.execute((await userInfoRequest(request)).parameters)
    );
  },

  revoke(request: NextRequest): Promise<Response> {
    return post(request, "POST revokeHandler", async () =>
      getContainer().revokeToken.execute((await formRequest(request)).parameters)
    );
  },

  listAccessTokens(request: NextRequest): Promise<Response> {
    return post(request, "POST listAccessTokensHandler", async () =>
      getContainer().listAccessTokens.execute((await formRequest(request)).parameters)
    );
  },

  revokeById(request: NextRequest): Promise<Response> {
    return post(request, "POST revokeByIdHandler", async () =>
      getContainer().revokeTokenById.execute((await formRequest(request)).parameters)
    );
  },

  revokeBySubject(request: NextRequest): Promise<Response> {
    return post(request, "POST revokeBySubjectHandler", async () =>
      getContainer().revokeTokensBySubject.execute((await formRequest(request)).parameters)
    );
  }
};

function post(
  request: NextRequest,
  handlerName: string,
  operation: Parameters<typeof executeController>[2]
): Promise<Response> {
  return executeController(request, { handlerName, allowedMethods: ["POST"] }, operation);
}
