import type {
  JwtPayload,
  OAuthAuthenticationProvider,
  OAuthClient,
  OAuthJwks
} from "../../types";
import {
  invalidClientResult,
  springParameterErrorResult,
  type OAuthResponseDto
} from "../dto/oauth-response.dto";
import type { OAuthRequestDto } from "../dto/oauth-request.dto";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";
import type { AuditRootCauseCode } from "../../domain/value-objects/audit-root-cause";
import { AuditEventService, type ClientAuthMethod } from "./audit-event.service";
import { ClientAssertionValidationService } from "./client-assertion-validation.service";

export type ClientAuth =
  | {
      ok: true;
      client: OAuthClient;
      method: ClientAuthMethod;
      assertionPayload?: JwtPayload;
    }
  | {
      ok: false;
      response: OAuthResponseDto;
    };

export class ClientAuthenticationService {
  private readonly auditEvents: AuditEventService;
  private readonly assertionValidation: ClientAssertionValidationService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.auditEvents = new AuditEventService(ports);
    this.assertionValidation = new ClientAssertionValidationService(ports);
  }

  async authenticate(
    request: OAuthRequestDto,
    options: {
      allowPublic: boolean;
      required: boolean;
      expectedClientId?: string;
      oauthFlowId: string;
    }
  ): Promise<ClientAuth> {
    const basic = parseBasicAuth(request.headers.authorization);
    if (basic) {
      const client = this.ports.state.getClient(basic.clientId);
      if (
        !client ||
        !client.authMethods.includes("client_secret_basic") ||
        !this.isClientSecretValid(client, basic.clientSecret)
      ) {
        return this.failed(
          invalidClientResult(),
          options.oauthFlowId,
          "invalid_client_secret",
          basic.clientId,
          "client_secret_basic"
        );
      }
      if (options.expectedClientId && options.expectedClientId !== client.clientId) {
        return this.failed(
          invalidClientResult(),
          options.oauthFlowId,
          "client_id_mismatch",
          client.clientId,
          "client_secret_basic"
        );
      }
      return this.succeeded(client, "client_secret_basic", options.oauthFlowId);
    }

    const assertion = request.parameters.client_assertion;
    const assertionType = request.parameters.client_assertion_type;
    if (assertion || assertionType) {
      if (assertionType !== this.ports.config.clientAssertionType) {
        return this.failed(
          springParameterErrorResult("client_assertion_type"),
          options.oauthFlowId,
          "invalid_client_assertion_type",
          undefined,
          "private_key_jwt"
        );
      }
      if (!assertion) {
        return this.failed(
          springParameterErrorResult("client_assertion"),
          options.oauthFlowId,
          "missing_client_assertion",
          undefined,
          "private_key_jwt"
        );
      }

      const validation = await this.assertionValidation.validate({
        assertion,
        acceptedAudiences: [
          request.baseUrl,
          `${request.baseUrl}/oauth2/v1/token`,
          request.requestUrl
        ],
        expectedClientId: options.expectedClientId,
        requireClientSubject: true
      });
      if (!validation.valid) {
        return this.failed(
          invalidClientResult(),
          options.oauthFlowId,
          validation.reasonCode,
          validation.clientId,
          "private_key_jwt",
          validation.rootCauseCode
        );
      }
      return this.succeeded(
        validation.client,
        "private_key_jwt",
        options.oauthFlowId,
        validation.payload,
        {
          kid: validation.header.kid,
          jti: validation.payload.jti
        }
      );
    }

    const clientId = request.parameters.client_id;
    if (clientId) {
      const client = this.ports.state.getClient(clientId);
      if (!client) {
        return this.failed(
          invalidClientResult(),
          options.oauthFlowId,
          "unknown_client",
          clientId,
          "none"
        );
      }
      if (options.expectedClientId && options.expectedClientId !== client.clientId) {
        return this.failed(
          invalidClientResult(),
          options.oauthFlowId,
          "client_id_mismatch",
          client.clientId,
          "none"
        );
      }
      if ((client.type === "public" && options.allowPublic) || !options.required) {
        return this.succeeded(client, "none", options.oauthFlowId);
      }
    }

    return this.failed(
      invalidClientResult(),
      options.oauthFlowId,
      options.required ? "client_authentication_required" : "invalid_client",
      clientId,
      "none"
    );
  }

  async resolveClientJwks(client: OAuthClient): Promise<OAuthJwks | null> {
    return this.ports.remoteJwks.resolve(client.jwks, client.jwksUri, {
      clientId: client.clientId
    });
  }

  async resolveAuthenticationProviderJwks(
    provider: OAuthAuthenticationProvider
  ): Promise<OAuthJwks | null> {
    return this.ports.remoteJwks.resolve(provider.jwks, provider.jwksUri, {
      providerId: provider.providerId
    });
  }

  private async succeeded(
    client: OAuthClient,
    method: ClientAuthMethod,
    oauthFlowId: string,
    assertionPayload?: JwtPayload,
    metadata: Record<string, unknown> = {}
  ): Promise<ClientAuth> {
    if (method === "none") {
      this.ports.loggers.clientAuth.info("Public client identified", {
        clientId: client.clientId,
        method,
        oauthFlowId,
        tags: ["oauth", "client"]
      });
      return { ok: true, client, method, assertionPayload };
    }

    const audit = await this.ports.audit.record({
      auditType: "client_authenticated",
      auditStatus: "SUCCESS",
      oauthFlowId,
      details: { clientId: client.clientId, authenticationMethod: method }
    });
    this.ports.loggers.clientAuth.info("Client authenticated", {
      clientId: client.clientId,
      method,
      ...metadata,
      ...this.ports.audit.correlation(audit),
      tags: ["oauth", "client-auth"]
    });
    return { ok: true, client, method, assertionPayload };
  }

  private async failed(
    response: OAuthResponseDto,
    oauthFlowId: string,
    reasonCode: string,
    clientId?: string,
    method?: ClientAuthMethod,
    rootCauseCode?: AuditRootCauseCode
  ): Promise<ClientAuth> {
    await this.auditEvents.recordClientAuthenticationFailure(
      oauthFlowId,
      reasonCode,
      clientId,
      method,
      rootCauseCode
    );
    return { ok: false, response };
  }

  private isClientSecretValid(client: OAuthClient, providedSecret: string): boolean {
    return Boolean(
      client.clientSecretHash &&
        this.ports.clientSecrets.verify(providedSecret, client.clientSecretHash)
    );
  }
}

function parseBasicAuth(
  header: string | undefined
): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return {
      clientId: decoded.slice(0, separator),
      clientSecret: decoded.slice(separator + 1)
    };
  } catch {
    return null;
  }
}
