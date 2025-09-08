import {
  OAuthClientProvider,
  auth,
} from "@modelcontextprotocol/sdk/client/auth.js";
import {
  OAuthClientInformationFull,
  OAuthClientInformationSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  IDE,
  MCPServerStatus,
  SSEOptions,
  StreamableHTTPOptions,
} from "../..";

import http from "http";
import url from "url";
import { GlobalContext, GlobalContextType } from "../../util/GlobalContext";
import { Mutex } from "async-mutex";

// Use a Map to track authentication contexts per server URL
// This prevents race conditions with concurrent auth attempts
const authenticationContexts = new Map<string, {
  authenticatingServer: MCPServerStatus;
  ide: IDE;
  mutex: Mutex;
}>();

// Global mutex for managing authentication state
const authenticationMutex = new Mutex();

const PORT = 3000;

const server = http.createServer((req, res) => {
  try {
    if (!req.url) {
      throw new Error("no url found");
    }

    const parsedUrl = url.parse(req.url, true);
    if (!parsedUrl.query["code"]) {
      throw new Error("no query params found");
    }

    void handleMCPOauthCode(parsedUrl.query["code"] as string);

    const html = `
<!DOCTYPE html>
<html>
<head><title>Authentication Complete</title></head>
<body>Authentication Complete. You can close this page now.</body>
</html>`;

    res.writeHead(200, {
      "Content-Type": "text/html",
    });
    res.end(html);
  } catch (error) {
    res.writeHead(400, { "Content-Type": "text/plain" });
    res.end(`Unexpected redirect error:  ${(error as Error).message}`);
  }
});

type MCPOauthStorage = GlobalContextType["mcpOauthStorage"][string];
type MCPOauthStorageKey = keyof MCPOauthStorage;
type MCPTransportWithOAuth = SSEOptions | StreamableHTTPOptions;

class MCPConnectionOauthProvider implements OAuthClientProvider {
  private globalContext: GlobalContext;

  constructor(
    public oauthServerUrl: string,
    private ide: IDE,
  ) {
    this.globalContext = new GlobalContext();
  }

  get redirectUrl() {
    return `http://localhost:${PORT}`; // TODO: this has to be a hub url or should we spin up a server?
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "Continue Dev, Inc", // get this from package.json?
      client_uri: "https://continue.dev", // get this from package.json?
    };
  }

  private _getOauthStorage<K extends MCPOauthStorageKey>(key: K) {
    return this.globalContext.get("mcpOauthStorage")?.[this.oauthServerUrl]?.[
      key
    ];
  }

  private _updateOauthStorage<K extends MCPOauthStorageKey>(
    key: K,
    value: MCPOauthStorage[K],
  ) {
    const existingStorage = this.globalContext.get("mcpOauthStorage") ?? {};
    const existingServerStorage = existingStorage[this.oauthServerUrl] ?? {};

    this.globalContext.update("mcpOauthStorage", {
      ...existingStorage,
      [this.oauthServerUrl]: {
        ...existingServerStorage,
        [key]: value,
      },
    });
  }

  private _clearOauthStorage() {
    const existingStorage = this.globalContext.get("mcpOauthStorage") ?? {};
    delete existingStorage[this.oauthServerUrl];
    this.globalContext.update("mcpOauthStorage", existingStorage);
  }

  saveClientInformation(clientInformation: OAuthClientInformationFull) {
    this._updateOauthStorage("clientInformation", clientInformation);
  }

  async clientInformation() {
    const existingClientInformation =
      this._getOauthStorage("clientInformation");
    if (!existingClientInformation) {
      return undefined;
    }
    return await OAuthClientInformationSchema.parseAsync(
      existingClientInformation,
    );
  }

  async tokens() {
    const existingTokens = this._getOauthStorage("tokens");
    if (!existingTokens) {
      return undefined;
    }
    return await OAuthTokensSchema.parseAsync(existingTokens);
  }

  saveTokens(tokens: OAuthTokens) {
    this._updateOauthStorage("tokens", tokens);
  }

  codeVerifier(): string | Promise<string> {
    const existingCodeVerifier = this._getOauthStorage("codeVerifier");
    if (!existingCodeVerifier) {
      return "";
    }
    return existingCodeVerifier;
  }

  saveCodeVerifier(codeVerifier: string) {
    this._updateOauthStorage("codeVerifier", codeVerifier);
  }

  clear() {
    this._clearOauthStorage();
  }

  async redirectToAuthorization(authorizationUrl: URL) {
    if (!server.listening) {
      server.listen(PORT, () => {
        console.debug(
          `Server started for MCP Oauth process at http://localhost:${PORT}/`,
        );
      });
    }
    void this.ide.openUrl(authorizationUrl.toString());
  }
}

export async function getOauthToken(mcpServerUrl: string, ide: IDE) {
  const authProvider = new MCPConnectionOauthProvider(mcpServerUrl, ide);
  const tokens = await authProvider.tokens();
  return tokens?.access_token;
}

function isOAuthSupportedTransport(
  transport: any,
): transport is MCPTransportWithOAuth {
  return (
    transport &&
    (transport.type === "sse" || transport.type === "streamable-http") &&
    typeof transport.url === "string"
  );
}

function getServerUrl(transport: MCPTransportWithOAuth): string {
  if (!transport.url) {
    throw new Error("Transport URL is required for OAuth authentication");
  }
  return transport.url;
}

/**
 * checks if the authentication is already done for the current server
 * if not, starts the authentication process by opening a webpage url
 */
export async function performAuth(mcpServer: MCPServerStatus, ide: IDE) {
  if (!isOAuthSupportedTransport(mcpServer.transport)) {
    throw new Error(`OAuth is not supported for transport type: ${mcpServer.transport.type}`);
  }
  const transport = mcpServer.transport;
  const mcpServerUrl = getServerUrl(transport);
  
  // Use mutex to prevent concurrent authentication attempts for the same server
  return await authenticationMutex.runExclusive(async () => {
    // Check if authentication is already in progress for this server
    if (authenticationContexts.has(mcpServerUrl)) {
      const context = authenticationContexts.get(mcpServerUrl)!;
      // Wait for the existing authentication to complete
      return await context.mutex.runExclusive(async () => {
        // Authentication is already complete by the time we get here
        const authProvider = new MCPConnectionOauthProvider(mcpServerUrl, ide);
        const tokens = await authProvider.tokens();
        return tokens ? "AUTHORIZED" : "UNAUTHORIZED";
      });
    }
    
    // Create new authentication context
    const authContext = {
      authenticatingServer: mcpServer,
      ide,
      mutex: new Mutex(),
    };
    authenticationContexts.set(mcpServerUrl, authContext);
    
    try {
      const authProvider = new MCPConnectionOauthProvider(mcpServerUrl, ide);
      return await auth(authProvider, {
        serverUrl: mcpServerUrl,
      });
    } catch (error) {
      // Clean up on error
      authenticationContexts.delete(mcpServerUrl);
      throw error;
    }
  });
}

/**
 * handle the authentication code received from the oauth redirect
 */
async function handleMCPOauthCode(authorizationCode: string) {
  // Find the authentication context that matches the current OAuth flow
  // We need to identify which server this auth code is for
  let authContext: { authenticatingServer: MCPServerStatus; ide: IDE; mutex: Mutex } | undefined;
  let serverUrl: string | undefined;
  
  // Since we can have multiple concurrent auth attempts, we need to identify
  // which one this code belongs to. For now, we'll use the first active context.
  // In a production system, you'd want to include a state parameter in the OAuth flow.
  for (const [url, context] of authenticationContexts.entries()) {
    authContext = context;
    serverUrl = url;
    break;
  }
  
  if (!authContext || !serverUrl) {
    console.error("No active authentication context found for OAuth callback");
    return;
  }
  
  const { ide, authenticatingServer } = authContext;

  if (!authorizationCode) {
    void ide.showToast(
      "error",
      `No MCP authorization code found for ${serverUrl}`,
    );
    authenticationContexts.delete(serverUrl);
    return;
  }
  
  // Close the OAuth server with proper error handling
  await new Promise<void>((resolve) => {
    server.close((error) => {
      if (error) {
        console.error("Error closing OAuth server:", error);
      } else {
        console.debug("Server for MCP Oauth process was closed");
      }
      resolve();
    });
  });
  
  try {
    await authContext.mutex.runExclusive(async () => {
      const authProvider = new MCPConnectionOauthProvider(serverUrl, ide);
      const authStatus = await auth(authProvider, {
        serverUrl,
        authorizationCode,
      });
      
      if (authStatus === "AUTHORIZED") {
        const { MCPManagerSingleton } = await import("./MCPManagerSingleton"); // put dynamic import to avoid cyclic imports
        await MCPManagerSingleton.getInstance().refreshConnection(
          authenticatingServer.id,
        );
      }
    });
  } finally {
    // Clean up the authentication context
    authenticationContexts.delete(serverUrl);
  }
}

export function removeMCPAuth(mcpServer: MCPServerStatus, ide: IDE) {
  if (!isOAuthSupportedTransport(mcpServer.transport)) {
    // Silently return if OAuth is not supported for this transport
    return;
  }
  const transport = mcpServer.transport;
  const mcpServerUrl = getServerUrl(transport);
  const authProvider = new MCPConnectionOauthProvider(mcpServerUrl, ide);
  authProvider.clear();
}
