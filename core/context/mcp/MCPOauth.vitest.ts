import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { GlobalContext } from "../../util/GlobalContext";
import { getGlobalContextFilePath } from "../../util/paths";
import { getOauthToken, performAuth, removeMCPAuth } from "./MCPOauth";

// Mock the MCP SDK auth module
vi.mock("@modelcontextprotocol/sdk/client/auth.js", () => ({
  auth: vi.fn(),
}));

// Mock the MCPManagerSingleton to avoid circular imports
vi.mock("./MCPManagerSingleton", () => ({
  MCPManagerSingleton: {
    getInstance: vi.fn(() => ({
      refreshConnection: vi.fn(),
    })),
  },
}));

describe("MCPOauth", () => {
  let globalContextFilePath: string;
  let mockIde: any;
  let mockSseMcpServer: any;
  let mockStreamableHttpMcpServer: any;

  beforeEach(() => {
    // file is present in the core/test directory
    globalContextFilePath = getGlobalContextFilePath();
    if (fs.existsSync(globalContextFilePath)) {
      fs.unlinkSync(globalContextFilePath);
    }

    mockIde = {
      openUrl: vi.fn(),
      showToast: vi.fn(),
    };

    mockSseMcpServer = {
      id: "test-sse-server",
      transport: {
        type: "sse",
        url: "https://test-sse-server.com",
      },
    };

    mockStreamableHttpMcpServer = {
      id: "test-streamable-server",
      transport: {
        type: "streamable-http",
        url: "https://test-streamable-server.com",
      },
    };

    vi.clearAllMocks();
  });

  afterEach(() => {
    if (fs.existsSync(globalContextFilePath)) {
      fs.unlinkSync(globalContextFilePath);
    }
  });

  describe("getOauthToken", () => {
    test("should return undefined when no tokens are stored", async () => {
      const result = await getOauthToken("https://test-server.com", mockIde);
      expect(result).toBeUndefined();
    });

    test("should return access token when tokens are stored", async () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://test-server.com": {
          tokens: {
            access_token: "test-access-token",
            token_type: "Bearer",
          },
        },
      });

      const result = await getOauthToken("https://test-server.com", mockIde);
      expect(result).toBe("test-access-token");
    });

    test("should handle different server URLs independently", async () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://server1.com": {
          tokens: {
            access_token: "token1",
            token_type: "Bearer",
          },
        },
        "https://server2.com": {
          tokens: {
            access_token: "token2",
            token_type: "Bearer",
          },
        },
      });

      const result1 = await getOauthToken("https://server1.com", mockIde);
      const result2 = await getOauthToken("https://server2.com", mockIde);
      const result3 = await getOauthToken("https://server3.com", mockIde);

      expect(result1).toBe("token1");
      expect(result2).toBe("token2");
      expect(result3).toBeUndefined();
    });
  });

  describe("performAuth", () => {
    test("should call auth with correct parameters for SSE transport", async () => {
      const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
      const mockAuth = vi.mocked(auth);
      mockAuth.mockResolvedValue("AUTHORIZED");

      const result = await performAuth(mockSseMcpServer, mockIde);

      expect(mockAuth).toHaveBeenCalledWith(
        expect.any(Object), // MCPConnectionOauthProvider instance
        {
          serverUrl: "https://test-sse-server.com",
        },
      );
      expect(result).toBe("AUTHORIZED");
    });

    test("should call auth with correct parameters for Streamable HTTP transport", async () => {
      const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
      const mockAuth = vi.mocked(auth);
      mockAuth.mockResolvedValue("AUTHORIZED");

      const result = await performAuth(mockStreamableHttpMcpServer, mockIde);

      expect(mockAuth).toHaveBeenCalledWith(
        expect.any(Object), // MCPConnectionOauthProvider instance
        {
          serverUrl: "https://test-streamable-server.com",
        },
      );
      expect(result).toBe("AUTHORIZED");
    });
  });

  describe("removeMCPAuth", () => {
    test("should clear oauth storage for SSE server", () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://test-sse-server.com": {
          tokens: {
            access_token: "test-access-token",
            token_type: "Bearer",
          },
          clientInformation: {
            client_id: "test-client-id",
            redirect_uris: ["http://localhost:3000"],
          },
          codeVerifier: "test-code-verifier",
        },
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });

      removeMCPAuth(mockSseMcpServer, mockIde);

      const updatedStorage = globalContext.get("mcpOauthStorage");
      expect(updatedStorage).toEqual({
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });
    });

    test("should clear oauth storage for Streamable HTTP server", () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://test-streamable-server.com": {
          tokens: {
            access_token: "test-access-token",
            token_type: "Bearer",
          },
          clientInformation: {
            client_id: "test-client-id",
            redirect_uris: ["http://localhost:3000"],
          },
          codeVerifier: "test-code-verifier",
        },
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });

      removeMCPAuth(mockStreamableHttpMcpServer, mockIde);

      const updatedStorage = globalContext.get("mcpOauthStorage");
      expect(updatedStorage).toEqual({
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });
    });

    test("should handle non-existent SSE server gracefully", () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });

      removeMCPAuth(mockSseMcpServer, mockIde);

      const updatedStorage = globalContext.get("mcpOauthStorage");
      expect(updatedStorage).toEqual({
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });
    });

    test("should handle non-existent Streamable HTTP server gracefully", () => {
      const globalContext = new GlobalContext();
      globalContext.update("mcpOauthStorage", {
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });

      removeMCPAuth(mockStreamableHttpMcpServer, mockIde);

      const updatedStorage = globalContext.get("mcpOauthStorage");
      expect(updatedStorage).toEqual({
        "https://other-server.com": {
          tokens: {
            access_token: "other-access-token",
            token_type: "Bearer",
          },
        },
      });
    });
  });
});
