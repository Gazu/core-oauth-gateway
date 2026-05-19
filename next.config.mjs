/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      { source: "/oauth2/authorize", destination: "/oauth2/v1/authorize" },
      { source: "/oauth2/par", destination: "/oauth2/v1/authorize/par" },
      { source: "/oauth2/token", destination: "/oauth2/v1/token" },
      { source: "/oauth2/revoke", destination: "/oauth2/v1/revoke" },
      { source: "/oauth2/jwks", destination: "/oauth2/v1/certs" }
    ];
  }
};

export default nextConfig;
