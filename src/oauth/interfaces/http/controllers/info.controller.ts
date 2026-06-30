import type { NextRequest } from "next/server";
import { getContainer } from "@/container";
import { jsonResult } from "@/oauth/application/dto/oauth-response.dto";
import { executeController } from "@/oauth/interfaces/http/controllers/controller-support";

export const infoController = {
  get(request: NextRequest): Promise<Response> {
    return executeController(
      request,
      { handlerName: "GET infoHandler", allowedMethods: ["GET"] },
      () => jsonResult(getContainer().getServiceInfo.execute())
    );
  }
};
