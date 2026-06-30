import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";

export const healthController = {
  get(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET healthHandler", allowedMethods: ["GET"] },
      () => getContainer().healthCheck.execute()
    );
  }
};
