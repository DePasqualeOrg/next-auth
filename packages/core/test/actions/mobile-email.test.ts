import { describe, it, expect, vi, beforeEach } from "vitest"
import { Auth } from "../../src/index.js"
import type { AuthConfig } from "../../src/types.js"

// Mock email provider
const mockEmailProvider = {
  id: "email",
  type: "email" as const,
  name: "Email",
  server: "smtp://localhost:587",
  from: "test@example.com",
  sendVerificationRequest: vi.fn(),
  generateVerificationToken: vi.fn(),
  maxAge: 86400, // 24 hours
}

// Mock adapter
const mockAdapter = {
  getUserByEmail: vi.fn(),
  createVerificationToken: vi.fn(),
  useVerificationToken: vi.fn(),
  createUser: vi.fn(), // Added createUser mock
}

// Mock configuration
const mockConfig: AuthConfig = {
  secret: "test-secret",
  trustHost: true,
  providers: [mockEmailProvider],
  adapter: mockAdapter,
}

describe("Mobile Email Magic Link Authentication", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("Mobile Email Send Token (POST /auth/mobile-signin/email)", () => {
    it("should send verification email and return success response", async () => {
      const email = "test@example.com"

      // Mock adapter responses
      mockAdapter.getUserByEmail.mockResolvedValue({
        id: "user-123",
        email,
        emailVerified: null,
      })
      mockAdapter.createVerificationToken.mockResolvedValue(undefined)

      // Mock email provider
      mockEmailProvider.sendVerificationRequest.mockResolvedValue(undefined)
      mockEmailProvider.generateVerificationToken.mockResolvedValue(
        "test-token"
      )

      const request = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(200)
      expect(result.message).toBe("Verification email sent")
      expect(result.email).toBe(email)

      // Verify email was sent
      expect(mockEmailProvider.sendVerificationRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: email,
          token: "test-token",
          url: expect.stringContaining("/mobile-callback/email"),
        })
      )

      // Verify token was stored
      expect(mockAdapter.createVerificationToken).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: email,
          expires: expect.any(Date),
        })
      )
    })

    it("should return error for missing email", async () => {
      const request = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Email address is required")
    })

    it("should return error for invalid email", async () => {
      const request = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "" }),
        }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Email address is required")
    })

    it("should handle email sending failure", async () => {
      const email = "test@example.com"

      mockAdapter.getUserByEmail.mockResolvedValue({
        id: "user-123",
        email,
        emailVerified: null,
      })

      // Mock email sending failure
      mockEmailProvider.sendVerificationRequest.mockRejectedValue(
        new Error("SMTP error")
      )

      const request = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Failed to send verification email")
    })

    it("should create new user if not exists", async () => {
      const email = "newuser@example.com"

      // Mock user doesn't exist
      mockAdapter.getUserByEmail.mockResolvedValue(null)
      mockAdapter.createVerificationToken.mockResolvedValue(undefined)
      mockEmailProvider.sendVerificationRequest.mockResolvedValue(undefined)

      const request = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(200)
      expect(result.message).toBe("Verification email sent")
      expect(result.email).toBe(email)
    })
  })

  describe("Mobile Email Callback (GET /auth/mobile-callback/email)", () => {
    it("should verify token and return JWT", async () => {
      const email = "test@example.com"
      const token = "verification-token"
      const user = {
        id: "user-123",
        name: "Test User",
        email,
        image: null,
      }

      // Mock successful token verification
      mockAdapter.useVerificationToken.mockResolvedValue({
        identifier: email,
        token: "hashed-token",
        expires: new Date(Date.now() + 86400000), // 24 hours from now
      })

      mockAdapter.getUserByEmail.mockResolvedValue(user)

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}&email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(200)
      expect(result.token).toBeDefined()
      expect(result.user).toEqual({
        id: user.id,
        name: user.name,
        email: user.email,
        image: user.image,
      })

      // Verify token was consumed
      expect(mockAdapter.useVerificationToken).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: email,
        })
      )
    })

    it("should return error for missing token parameter", async () => {
      const email = "test@example.com"

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Missing token or email parameter")
    })

    it("should return error for missing email parameter", async () => {
      const token = "verification-token"

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Missing token or email parameter")
    })

    it("should return error for invalid token", async () => {
      const email = "test@example.com"
      const token = "invalid-token"

      // Mock token not found
      mockAdapter.useVerificationToken.mockResolvedValue(null)

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}&email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Email verification failed")
    })

    it("should return error for expired token", async () => {
      const email = "test@example.com"
      const token = "expired-token"

      // Mock expired token
      mockAdapter.useVerificationToken.mockResolvedValue({
        identifier: email,
        token: "hashed-token",
        expires: new Date(Date.now() - 86400000), // 24 hours ago (expired)
      })

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}&email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Email verification failed")
    })

    it("should return error for email mismatch", async () => {
      const email = "test@example.com"
      const differentEmail = "different@example.com"
      const token = "verification-token"

      // Mock token with different email
      mockAdapter.useVerificationToken.mockResolvedValue({
        identifier: differentEmail,
        token: "hashed-token",
        expires: new Date(Date.now() + 86400000),
      })

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}&email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(400)
      expect(result.error).toBe("Email verification failed")
    })

    it("should create user if not exists during callback", async () => {
      const email = "newuser@example.com"
      const token = "verification-token"

      // Mock successful token verification but user doesn't exist
      mockAdapter.useVerificationToken.mockResolvedValue({
        identifier: email,
        token: "hashed-token",
        expires: new Date(Date.now() + 86400000),
      })

      mockAdapter.getUserByEmail.mockResolvedValue(null)
      mockAdapter.createUser.mockResolvedValue({
        id: "new-user-id",
        email: email,
        emailVerified: new Date(),
      })

      const request = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=${token}&email=${email}`,
        { method: "GET" }
      )

      const response = await Auth(request, mockConfig)
      const result = await response.json()

      expect(response.status).toBe(200)
      expect(result.token).toBeDefined()
      expect(result.user.email).toBe(email)
      expect(result.user.id).toBeDefined()
    })
  })

  describe("Mobile Email Integration", () => {
    it("should handle complete email magic link flow", async () => {
      const email = "integration@example.com"

      // Step 1: Send magic link
      mockAdapter.getUserByEmail.mockResolvedValue({
        id: "user-123",
        email,
        emailVerified: null,
      })
      mockAdapter.createVerificationToken.mockResolvedValue(undefined)
      mockEmailProvider.sendVerificationRequest.mockResolvedValue(undefined)
      mockEmailProvider.generateVerificationToken.mockResolvedValue(
        "integration-token"
      )

      const sendRequest = new Request(
        "http://localhost:3000/auth/mobile-signin/email",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        }
      )

      const sendResponse = await Auth(sendRequest, mockConfig)
      const sendResult = await sendResponse.json()

      expect(sendResponse.status).toBe(200)
      expect(sendResult.message).toBe("Verification email sent")

      // Step 2: Verify token
      mockAdapter.useVerificationToken.mockResolvedValue({
        identifier: email,
        token: "hashed-integration-token",
        expires: new Date(Date.now() + 86400000),
      })

      const callbackRequest = new Request(
        `http://localhost:3000/auth/mobile-callback/email?token=integration-token&email=${email}`,
        { method: "GET" }
      )

      const callbackResponse = await Auth(callbackRequest, mockConfig)
      const callbackResult = await callbackResponse.json()

      expect(callbackResponse.status).toBe(200)
      expect(callbackResult.token).toBeDefined()
      expect(callbackResult.user.email).toBe(email)
    })
  })
})
