import type { NextRequest } from "next/server";
import type { OAuthResponseDto } from "@/oauth/application/dto/oauth-response.dto";
import { emptyResult } from "@/oauth/application/dto/oauth-response.dto";
import { handleNextRequest } from "@/oauth/infrastructure/http/next-route-handler";
import { presentOAuthResponse } from "@/oauth/interfaces/http/presenters/oauth-response.presenter";
import { validateRouteMethod } from "@/oauth/interfaces/http/validators/route.validator";

type ControllerOptions = {
  handlerName: string;
  allowedMethods: readonly string[];
};

export function executeController(
  request: NextRequest,
  options: ControllerOptions,
  operation: () => Promise<OAuthResponseDto> | OAuthResponseDto
): Promise<Response> {
  return handleNextRequest(request, options.handlerName, async () => {
    const validationResponse = validateRouteMethod(request, options.allowedMethods);
    if (validationResponse) {
      return presentOAuthResponse(
        emptyResult({
          status: validationResponse.status,
          headers: Object.fromEntries(validationResponse.headers.entries())
        })
      );
    }
    return presentOAuthResponse(await operation());
  });
}
