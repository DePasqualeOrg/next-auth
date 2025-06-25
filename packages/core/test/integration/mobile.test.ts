import { describe, it, expect, vi } from "vitest"
import { Auth } from "../../src"
import type { CredentialsConfig } from "../../src/providers"

describe("Mobile Authentication Integration Tests", () => {
  const mockCredentialsProvider: CredentialsConfig = {
    id: "credentials",
    name: "Credentials",
    type: "credentials",
    credentials: {
      username: { label: "Username", type: "text" },
      password: { label: "Password", type: "password" },
    },
    authorize: vi.fn(async (credentials) => {
      if (
        credentials?.username === "test@example.com" &&
        credentials?.password === "password123"
      ) {
        return {
          id: "1",
          email: "test@example.com",
          name: "Test User",
        }
      }
      return null
    }),
  }

  const authConfig = {
    providers: [mockCredentialsProvider],
    secret: "test-secret",
    trustHost: true,
    skipCSRFCheck: () => true,
    session: {
      maxAge: 30 * 24 * 60 * 60, // 30 days
    },
  }

  it("should handle mobile-signin with Web API Request object", async () => {
    // Create a Web API Request object like a real mobile integration would
    const requestBody = JSON.stringify({
      providerId: "credentials",
      username: "test@example.com",
      password: "password123",
    })

    const request = new Request("http://localhost:3000/auth/mobile-signin", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: requestBody,
    })

    // This should reproduce the request.headers.entries error
    const response = await Auth(request, authConfig)

    expect(response.status).toBe(200)

    const responseBody = await response.json()
    expect(responseBody).toHaveProperty("token")
    expect(responseBody).toHaveProperty("user")
    expect(responseBody.user.email).toBe("test@example.com")
  })

  it("should handle mobile-session with Web API Request object", async () => {
    // First, get a token from mobile-signin
    const signinRequest = new Request(
      "http://localhost:3000/auth/mobile-signin",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          providerId: "credentials",
          username: "test@example.com",
          password: "password123",
        }),
      }
    )

    const signinResponse = await Auth(signinRequest, authConfig)
    expect(signinResponse.status).toBe(200)

    const signinBody = await signinResponse.json()
    const token = signinBody.token

    // Now test mobile-session with the token
    const sessionRequest = new Request(
      "http://localhost:3000/auth/mobile-session",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    const sessionResponse = await Auth(sessionRequest, authConfig)
    expect(sessionResponse.status).toBe(200)

    const sessionBody = await sessionResponse.json()
    expect(sessionBody).toHaveProperty("user")
    expect(sessionBody.user.email).toBe("test@example.com")
  })

  it("should handle mobile-signout with Web API Request object", async () => {
    // First, get a token from mobile-signin
    const signinRequest = new Request(
      "http://localhost:3000/auth/mobile-signin",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          providerId: "credentials",
          username: "test@example.com",
          password: "password123",
        }),
      }
    )

    const signinResponse = await Auth(signinRequest, authConfig)
    const signinBody = await signinResponse.json()
    const token = signinBody.token

    // Now test mobile-signout
    const signoutRequest = new Request(
      "http://localhost:3000/auth/mobile-signout",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    const signoutResponse = await Auth(signoutRequest, authConfig)
    expect(signoutResponse.status).toBe(200)

    const signoutBody = await signoutResponse.json()
    expect(signoutBody).toHaveProperty("message")
  })

  it("should handle invalid credentials with Web API Request object", async () => {
    const request = new Request("http://localhost:3000/auth/mobile-signin", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        providerId: "credentials",
        username: "invalid@example.com",
        password: "wrongpassword",
      }),
    })

    const response = await Auth(request, authConfig)
    expect(response.status).toBe(401)

    const responseBody = await response.json()
    expect(responseBody).toHaveProperty("error")
  })

  it("should handle missing authorization header in mobile-session", async () => {
    const request = new Request("http://localhost:3000/auth/mobile-session", {
      method: "GET",
    })

    const response = await Auth(request, authConfig)
    expect(response.status).toBe(401)

    const responseBody = await response.json()
    expect(responseBody).toHaveProperty("error")
  })

  it("should handle invalid token in mobile-session", async () => {
    const request = new Request("http://localhost:3000/auth/mobile-session", {
      method: "GET",
      headers: {
        Authorization: "Bearer invalid-token",
      },
    })

    const response = await Auth(request, authConfig)
    expect(response.status).toBe(401)

    const responseBody = await response.json()
    expect(responseBody).toHaveProperty("error")
  })
})
