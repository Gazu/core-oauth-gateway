import { NextRequest } from "next/server";
import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  vi.stubEnv("LOGGER_MODE", "sync");
});

describe("Next route infrastructure", () => {
  it("preserves the response and applies one shared trace/request id", async () => {
    const { jsonResponse } = await import("../src/oauth/http");
    const { withOAuthRequestLogging } = await import("../src/oauth/logger");
    const requestId = "a1a8ed7a-2f55-4bb4-83be-074ebca4ea7e";
    const traceId = "4d521de94ce7dccca3720118022ca6a8";
    const handler = withOAuthRequestLogging("GET contract", async () => {
      return jsonResponse({ status: "ok" }, {
        status: 202,
        headers: { "X-Contract": "preserved" }
      });
    });

    const response = await handler(new NextRequest("http://localhost:3000/contract", {
      headers: {
        "X-Request-Id": requestId,
        "X-B3-TraceId": traceId,
        "X-B3-SpanId": "0123456789abcdef"
      }
    }));

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ status: "ok" });
    expect(response.headers.get("X-Contract")).toBe("preserved");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("X-Request-Id")).toBe(requestId);
    expect(response.headers.get("X-B3-TraceId")).toBe(traceId);
    expect(response.headers.get("Gazu-OAuth-Request-Id")).toBe(requestId);
    expect(response.headers.get("X-Service-Name")).toBe("core-oauth-gateway");
    expect(response.headers.get("X-Service-Version")).toBe("0.1.0");
  });

  it("does not expose unexpected error details", async () => {
    const { withOAuthRequestLogging } = await import("../src/oauth/logger");
    const handler = withOAuthRequestLogging("GET failure", async () => {
      throw new Error("database password leaked");
    });
    const response = await handler(new NextRequest("http://localhost:3000/failure"));
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: "internal_server_error",
      error_description: "Internal server error"
    });
    expect(JSON.stringify(body)).not.toContain("database password leaked");
  });
});
