import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";
import { formRequest } from "@/oauth/interfaces/http/validators/oauth-request.mapper";

export const tokenController = {
  issue(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "POST tokenHandler", allowedMethods: ["POST"] },
      async () => getContainer().issueToken.execute(await formRequest(request))
    );
  }
};
