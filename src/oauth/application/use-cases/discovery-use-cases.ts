import { jsonResult, type OAuthResponseDto } from "../dto/oauth-response.dto";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

export class GetDiscoveryDocumentUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  execute(baseUrl: string): OAuthResponseDto {
    return jsonResult({
      request_parameter_supported: true,
      authorization_signed_response_alg: ["RS256"],
      pushed_authorization_request_endpoint: `${baseUrl}/oauth2/v1/authorize/par`,
      scopes_supported: this.ports.config.supportedScopes,
      backchannel_logout_supported: true,
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth2/v1/authorize`,
      service_documentation:
        "https://docs.spring.io/spring-authorization-server/reference/getting-started.html",
      claims_supported: ["sub", "email", "user_id"],
      require_pushed_authorization_requests: false,
      token_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic"],
      response_modes_supported: ["query", "query.jwt", "jwt"],
      backchannel_logout_session_supported: true,
      token_endpoint: `${baseUrl}/oauth2/v1/token`,
      response_types_supported: ["code"],
      revocation_endpoint_auth_signing_alg_values_supported: [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512"
      ],
      revocation_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic"],
      request_uri_parameter_supported: false,
      grant_types_supported: [
        "authorization_code",
        "client_credentials",
        ...(this.ports.config.passwordGrantEnabled ? ["password"] : []),
        "refresh_token",
        this.ports.config.jwtBearerGrant,
        this.ports.config.tokenExchangeGrant
      ],
      revocation_endpoint: `${baseUrl}/oauth2/v1/revoke`,
      introspection_endpoint: `${baseUrl}/oauth2/v1/introspect`,
      userinfo_endpoint: `${baseUrl}/oauth2/v1/userinfo`,
      token_endpoint_auth_signing_alg_values_supported: [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512"
      ],
      code_challenge_methods_supported: ["S256"],
      jwks_uri: `${baseUrl}/oauth2/v1/certs`,
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256", "ES256"]
    });
  }
}

export class GetSigningCertificatesUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(): Promise<OAuthResponseDto> {
    return jsonResult({ keys: await this.ports.jwt.publicJwks() });
  }
}
