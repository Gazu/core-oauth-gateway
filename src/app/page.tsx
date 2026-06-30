const endpoints = [
  ["GET", "/.well-known/openid-configuration"],
  ["GET", "/info"],
  ["GET", "/health"],
  ["GET", "/oauth2/v1/authorize"],
  ["POST", "/oauth2/v1/authorize/par"],
  ["POST", "/oauth2/v1/token"],
  ["POST", "/oauth2/v1/tokeninfo"],
  ["GET", "/oauth2/v1/certs"],
  ["POST", "/oauth2/v1/revoke"],
  ["POST", "/oauth2/v1/listAccessTokens"]
] as const;

export default function Home() {
  return (
    <main>
      <section className="topbar">
        <div>
          <h1>core-oauth-gateway</h1>
          <p>Servicio OAuth2/OIDC local con endpoints versionados bajo /oauth2/v1.</p>
        </div>
        <div className="status">
          <span className="dot" />
          Ready
        </div>
      </section>

      <section className="grid" aria-label="OAuth service summary">
        <div className="panel">
          <h2>Endpoints</h2>
          <ul className="endpoint-list">
            {endpoints.map(([method, path]) => (
              <li className="endpoint" key={`${method}-${path}`}>
                <span className="method">{method}</span>
                <code>{path}</code>
              </li>
            ))}
          </ul>
        </div>

        <div className="panel">
          <h2>Smoke test</h2>
          <pre>{`curl -i http://localhost:3000/.well-known/openid-configuration

curl -i http://localhost:3000/oauth2/v1/token \\
  -X POST \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'grant_type=client_credentials&client_id=<client-id>&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<client-assertion>&scope=standard openid'`}</pre>
        </div>
      </section>
    </main>
  );
}
