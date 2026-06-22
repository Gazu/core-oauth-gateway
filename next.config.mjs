/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  experimental: {
    serverComponentsExternalPackages: [
      "@smb-tech/service-framework-js",
      "@smb-tech/logger-core",
      "@smb-tech/logger-node"
    ]
  }
};

export default nextConfig;
