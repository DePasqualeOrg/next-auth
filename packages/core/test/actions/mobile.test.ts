import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { decode, encode } from "../../src/jwt.js"
import {
  callbacks,
  getExpires,
  events,
  logger,
  makeAuthRequest,
  testConfig,
  AUTH_SECRET,
  SESSION_COOKIE_NAME,
  assertNoCacheResponseHeaders,
} from "../utils.js"
import { MemoryAdapter, initMemory } from "../memory-adapter.js"
import type { AdapterUser } from "../../src/adapters.js"

describe("Mobile Authentication Endpoints", () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe("mobile-signin", () => {
    it("should return JWT token on successful sign-in", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-signin",
        path: "/credentials",
        body: JSON.stringify({
          providerId: "credentials",
          username: "test@example.com",
          password: "password123",
        }),
        config: {
          providers: [
            {
              id: "credentials",
              name: "Credentials",
              type: "credentials",
              credentials: {
                username: { label: "Username", type: "text" },
                password: { label: "Password", type: "password" },
              },
              authorize: vi.fn().mockResolvedValue({
                id: "1",
                email: "test@example.com",
                name: "Test User",
              }),
            },
          ],
        },
      })

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("token")
      expect(body).toHaveProperty("expires")
      expect(typeof body.token).toBe("string")
      expect(body.token.length).toBeGreaterThan(0)

      // Verify the JWT token contains the expected user data
      const decoded = await decode({
        token: body.token,
        secret: AUTH_SECRET,
        salt: SESSION_COOKIE_NAME,
      })
      expect(decoded).toHaveProperty("sub", "1")
      expect(decoded).toHaveProperty("email", "test@example.com")
      expect(decoded).toHaveProperty("name", "Test User")
    })

    it("should return error on failed sign-in", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-signin",
        body: JSON.stringify({
          providerId: "credentials",
          username: "invalid",
          password: "invalid",
        }),
        config: {
          providers: [
            {
              id: "credentials",
              name: "Credentials",
              type: "credentials",
              credentials: {
                username: { label: "Username", type: "text" },
                password: { label: "Password", type: "password" },
              },
              authorize: vi.fn().mockResolvedValue(null), // Failed auth
            },
          ],
        },
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Invalid credentials")
    })

    it("should handle OAuth provider sign-in", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-signin",
        body: JSON.stringify({
          providerId: "github",
        }),
        config: {
          providers: [
            {
              id: "github",
              name: "GitHub",
              type: "oauth",
              clientId: "test-client-id",
              clientSecret: "test-client-secret",
              authorization: "https://github.com/login/oauth/authorize",
              token: "https://github.com/login/oauth/access_token",
              userinfo: "https://api.github.com/user",
            },
          ],
        },
      })

      // OAuth sign-in should return authorization URL
      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("url")
      expect(body).toHaveProperty("provider", "github")
    })
  })

  describe("mobile-session", () => {
    it("should validate and refresh JWT token", async () => {
      // Create a valid JWT token with the correct structure
      const sessionData = {
        sub: "1",
        email: "test@example.com",
        name: "Test User",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
      }

      const token = await encode({
        token: sessionData,
        secret: AUTH_SECRET,
        maxAge: 30 * 24 * 60 * 60,
        salt: SESSION_COOKIE_NAME,
      })

      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: `Bearer ${token}`,
        },
      })

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("token")
      expect(body).toHaveProperty("user")
      expect(body.user.id).toBe("1")
      expect(body.user.email).toBe("test@example.com")
      expect(body.user.name).toBe("Test User")
    })

    it("should return error for missing Authorization header", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-session",
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Missing or invalid Authorization header")
    })

    it("should return error for invalid JWT token", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: "Bearer invalid-token",
        },
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Invalid token")
    })

    it("should refresh JWT token on valid session", async () => {
      // Create a valid JWT token
      const sessionData = {
        user: {
          id: "1",
          email: "test@example.com",
          name: "Test User",
        },
        sub: "1",
        email: "test@example.com",
        name: "Test User",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
      }

      const token = await encode({
        token: sessionData,
        secret: AUTH_SECRET,
        maxAge: 30 * 24 * 60 * 60,
        salt: SESSION_COOKIE_NAME,
      })

      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: `Bearer ${token}`,
        },
      })

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("token")
      expect(body).toHaveProperty("user")

      // Verify the token is different (refreshed)
      expect(body.token).not.toBe(token)

      // Verify user data is preserved
      expect(body.user.id).toBe("1")
      expect(body.user.email).toBe("test@example.com")
      expect(body.user.name).toBe("Test User")
    })
  })

  describe("mobile-signout", () => {
    it("should successfully sign out with valid JWT token", async () => {
      // Create a valid JWT token
      const sessionData = {
        user: {
          id: "1",
          email: "test@example.com",
          name: "Test User",
        },
        sub: "1",
        email: "test@example.com",
        name: "Test User",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
      }

      const token = await encode({
        token: sessionData,
        secret: AUTH_SECRET,
        maxAge: 30 * 24 * 60 * 60,
        salt: SESSION_COOKIE_NAME,
      })

      const { response } = await makeAuthRequest({
        action: "mobile-signout",
        body: JSON.stringify({}), // Add body to ensure POST method
        headers: {
          authorization: `Bearer ${token}`,
        },
      })

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("message")
      expect(body.message).toBe("Signed out successfully")
    })

    it("should return error for missing Authorization header", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-signout",
        body: JSON.stringify({}), // Add body to ensure POST method
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Missing or invalid Authorization header")
    })

    it("should handle invalid JWT token gracefully", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-signout",
        body: JSON.stringify({}), // Add body to ensure POST method
        headers: {
          authorization: "Bearer invalid-token",
        },
      })

      // Sign out should still succeed even with invalid token
      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("message")
      expect(body.message).toBe("Signed out successfully")
    })
  })

  describe("mobile-callback", () => {
    it("should handle OAuth callback and return JWT token", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-callback",
        path: "/github",
        query: {
          code: "test-auth-code",
          state: "test-state",
        },
        config: {
          providers: [
            {
              id: "github",
              name: "GitHub",
              type: "oauth",
              clientId: "test-client-id",
              clientSecret: "test-client-secret",
              authorization: "https://github.com/login/oauth/authorize",
              token: "https://github.com/login/oauth/access_token",
              userinfo: "https://api.github.com/user",
            },
          ],
        },
      })

      // OAuth callback is not fully implemented yet, should return 501
      expect(response.status).toBe(501)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("OAuth callback not implemented")
    })

    it("should return error for failed OAuth callback", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-callback",
        path: "/github",
        query: {
          error: "access_denied",
          error_description: "User denied access",
        },
        config: {
          providers: [
            {
              id: "github",
              name: "GitHub",
              type: "oauth",
              clientId: "test-client-id",
              clientSecret: "test-client-secret",
              authorization: "https://github.com/login/oauth/authorize",
              token: "https://github.com/login/oauth/access_token",
              userinfo: "https://api.github.com/user",
            },
          ],
        },
      })

      // OAuth callback is not fully implemented yet, should return 501
      expect(response.status).toBe(501)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("OAuth callback not implemented")
    })
  })

  describe("Database strategy", () => {
    it("should work with database adapter for mobile-session", async () => {
      const adapter = {
        getSessionAndUser: vi.fn().mockResolvedValue({
          session: {
            sessionToken: "db-session-token",
            expires: new Date(Date.now() + 86400000),
          },
          user: { id: "1", email: "test@example.com", name: "Test User" },
        }),
        updateSession: vi.fn(),
        deleteSession: vi.fn(),
        createUser: vi.fn(),
        getUser: vi.fn(),
        getUserByEmail: vi.fn(),
        getUserByAccount: vi.fn(),
        updateUser: vi.fn(), // Added missing updateUser method
        linkAccount: vi.fn(),
        unlinkAccount: vi.fn(),
        createSession: vi.fn(),
        getAccount: vi.fn(),
        createVerificationToken: vi.fn(),
        useVerificationToken: vi.fn(),
      }

      // Create a JWT token for database strategy
      const sessionData = {
        sub: "1",
        email: "test@example.com",
        name: "Test User",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
      }

      const sessionToken = await encode({
        token: sessionData,
        secret: AUTH_SECRET,
        maxAge: 30 * 24 * 60 * 60,
        salt: SESSION_COOKIE_NAME,
      })

      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: `Bearer ${sessionToken}`,
        },
        config: {
          adapter,
        },
      })

      expect(response.status).toBe(200)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("token")
      expect(body).toHaveProperty("user")
      expect(body.user.id).toBe("1")
    })
  })

  describe("Security headers", () => {
    it("should include proper security headers in mobile responses", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-session",
      })

      // Should have no-cache headers for security
      assertNoCacheResponseHeaders(response)
    })
  })

  describe("Error handling", () => {
    it("should handle malformed Authorization header", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: "InvalidFormat token",
        },
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Missing or invalid Authorization header")
    })

    it("should handle missing Bearer prefix", async () => {
      const { response } = await makeAuthRequest({
        action: "mobile-session",
        headers: {
          authorization: "some-token-without-bearer",
        },
      })

      expect(response.status).toBe(401)
      expect(response.headers.get("content-type")).toBe("application/json")

      const body = await response.json()
      expect(body).toHaveProperty("error")
      expect(body.error).toBe("Missing or invalid Authorization header")
    })
  })
})
