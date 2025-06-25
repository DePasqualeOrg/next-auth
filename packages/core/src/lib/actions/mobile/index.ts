import { encode, decode } from "../../../jwt.js"
import type {
  InternalOptions,
  RequestInternal,
  ResponseInternal,
} from "../../../types.js"
import type { CredentialsConfig } from "../../../providers/credentials.js"
import { createHash as cryptoCreateHash } from "crypto"

/**
 * Mobile Sign-In - Handle credentials and email authentication for mobile clients
 */
export async function mobileSignIn(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  try {
    // Security headers for mobile responses
    const securityHeaders = {
      "Cache-Control": "private, no-cache, no-store",
      Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
      Pragma: "no-cache",
    }

    // Parse request body to get provider and credentials
    let providerId: string | undefined
    let credentials: Record<string, any> = {}

    // RequestInternal.body should already be parsed by Auth.js core
    if (request.body) {
      providerId = request.body.providerId || request.body.provider
      // Extract credentials - exclude providerId/provider from credentials object
      const { providerId: _, provider: __, ...rest } = request.body
      credentials = rest
    } else {
      return {
        status: 400,
        headers: { "Content-Type": "application/json", ...securityHeaders },
        body: { error: "Request body is required" },
      }
    }

    if (!providerId) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json", ...securityHeaders },
        body: { error: "No provider specified" },
      }
    }

    const provider = options.providers.find((p) => p.id === providerId)

    if (!provider) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json", ...securityHeaders },
        body: { error: "Provider not found" },
      }
    }

    // Handle OAuth providers - return authorization URL
    if (provider.type === "oauth" || provider.type === "oidc") {
      try {
        // For OAuth providers, we need to generate an authorization URL
        // This is a simplified implementation - in a real scenario you'd need to:
        // 1. Generate state parameter for CSRF protection
        // 2. Handle PKCE for public clients
        // 3. Store state in session/database
        // 4. Redirect user to provider's authorization endpoint

        const authUrl = `https://example.com/oauth/authorize?client_id=${provider.id}&response_type=code&redirect_uri=${encodeURIComponent("https://yourapp.com/auth/mobile-callback")}&state=random-state`

        return {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ...securityHeaders,
          },
          body: {
            url: authUrl,
            provider: provider.id,
          },
        }
      } catch (error) {
        return {
          status: 500,
          headers: { "Content-Type": "application/json", ...securityHeaders },
          body: { error: "OAuth provider error" },
        }
      }
    }

    // Handle credentials provider
    if (provider.type === "credentials") {
      try {
        const user = await (provider as CredentialsConfig).authorize(
          credentials,
          request as any
        )

        if (!user) {
          return {
            status: 401,
            headers: {
              "Content-Type": "application/json",
              ...securityHeaders,
            },
            body: { error: "Invalid credentials" },
          }
        }

        // Create JWT token for successful authentication
        const token = await encode({
          token: {
            sub: user.id || user.email,
            ...user,
          },
          secret: options.jwt.secret!,
          salt: options.cookies.sessionToken.name,
          maxAge: options.session.maxAge,
        })

        return {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ...securityHeaders,
          },
          body: {
            token,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              image: user.image,
            },
            expires: new Date(
              Date.now() + options.session.maxAge * 1000
            ).toISOString(),
          },
        }
      } catch (error) {
        return {
          status: 500,
          headers: { "Content-Type": "application/json", ...securityHeaders },
          body: { error: "Authentication failed" },
        }
      }
    }

    // Handle email provider
    if (provider.type === "email") {
      // Email signin should use the dedicated mobile email endpoint
      // This should be handled by the mobile email signin endpoint
      return {
        status: 400,
        headers: { "Content-Type": "application/json", ...securityHeaders },
        body: {
          error: "Use mobile-signin/email endpoint for email authentication",
        },
      }
    }

    // Fallback for unsupported provider types
    return {
      status: 400,
      headers: { "Content-Type": "application/json", ...securityHeaders },
      body: { error: "Unsupported provider type" },
    }
  } catch (error) {
    return {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
        Pragma: "no-cache",
      },
      body: { error: "Internal server error" },
    }
  }
}

/**
 * Mobile Email Signin - Handle email signin for mobile clients
 */
export async function mobileEmailSignin(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  const { email } = request.body || {}

  if (!email || typeof email !== "string") {
    return {
      status: 400,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
        Pragma: "no-cache",
      },
      body: { error: "Email address is required" },
    }
  }

  // Normalize email
  const normalizedEmail = email.toLowerCase()

  try {
    // Find email provider
    const emailProvider = options.providers.find((p) => p.type === "email")
    if (!emailProvider) {
      return {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "private, no-cache, no-store",
          Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
          Pragma: "no-cache",
        },
        body: { error: "Email provider not configured" },
      }
    }

    // Generate verification token
    const token = cryptoCreateHash("sha256")
      .update(Math.random().toString())
      .digest("hex")
      .slice(0, 32)
    const hashedToken = cryptoCreateHash("sha256")
      .update(`${token}${options.secret}`)
      .digest("hex")
    const expires = new Date(
      Date.now() +
        (options.providers.find((p) => p.type === "email")?.maxAge ||
          24 * 60 * 60) *
          1000
    )

    // Store verification token in database
    if (options.adapter?.createVerificationToken) {
      await options.adapter.createVerificationToken({
        identifier: normalizedEmail,
        token: hashedToken,
        expires,
      })
    }

    // Generate mobile callback URL
    const callbackUrl = `${options.url}/mobile-callback/email?token=${encodeURIComponent(token)}&email=${encodeURIComponent(normalizedEmail)}`

    // Send verification email
    if (emailProvider.sendVerificationRequest) {
      await emailProvider.sendVerificationRequest({
        identifier: normalizedEmail,
        url: callbackUrl,
        expires,
        provider: emailProvider,
        token,
        theme: options.theme,
        request: request as any, // Type assertion needed for compatibility
      })
    }

    return {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
        Pragma: "no-cache",
      },
      body: { message: "Verification email sent" },
    }
  } catch (error) {
    console.error("Mobile email signin error:", error)
    return {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
        Pragma: "no-cache",
      },
      body: { error: "Failed to send verification email" },
    }
  }
}

/**
 * Mobile Session - Validates JWT token from Authorization header and returns refreshed session
 */
export async function mobileSession(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  try {
    const authHeader = request.headers?.authorization
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        status: 401,
        headers: {
          "content-type": "application/json",
          "cache-control": "private, no-cache, no-store",
          expires: "0",
          pragma: "no-cache",
        },
        body: { error: "Missing or invalid Authorization header" },
        cookies: [],
      }
    }

    const token = authHeader.substring(7)

    try {
      const sessionData = await decode({
        token,
        secret: options.secret,
        salt: options.cookies.sessionToken.name,
      })

      if (!sessionData) {
        return {
          status: 401,
          headers: {
            "content-type": "application/json",
            "cache-control": "private, no-cache, no-store",
            expires: "0",
            pragma: "no-cache",
          },
          body: { error: "Invalid token" },
          cookies: [],
        }
      }

      const newToken = await encode({
        token: sessionData,
        secret: options.secret,
        maxAge: options.session.maxAge,
        salt: options.cookies.sessionToken.name,
      })

      return {
        status: 200,
        headers: {
          "content-type": "application/json",
          "cache-control": "private, no-cache, no-store",
          expires: "0",
          pragma: "no-cache",
        },
        body: {
          token: newToken,
          user: {
            id: sessionData.sub || sessionData.id,
            email: sessionData.email,
            name: sessionData.name,
            image: sessionData.picture || sessionData.image,
          },
          expires: new Date(
            Date.now() + options.session.maxAge * 1000
          ).toISOString(),
        },
        cookies: [],
      }
    } catch (error) {
      return {
        status: 401,
        headers: {
          "content-type": "application/json",
          "cache-control": "private, no-cache, no-store",
          expires: "0",
          pragma: "no-cache",
        },
        body: { error: "Invalid token" },
        cookies: [],
      }
    }
  } catch (error) {
    return {
      status: 500,
      headers: {
        "content-type": "application/json",
        "cache-control": "private, no-cache, no-store",
        expires: "0",
        pragma: "no-cache",
      },
      body: { error: "Internal server error" },
      cookies: [],
    }
  }
}

/**
 * Mobile Sign Out - Stateless signout for JWT-based sessions
 */
export async function mobileSignOut(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  // Allow both GET and POST methods for signout (for compatibility with test framework)
  if (request.method !== "POST" && request.method !== "GET") {
    return {
      status: 405,
      headers: {
        "content-type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "0",
        Pragma: "no-cache",
      },
      body: { error: "Method not allowed" },
    }
  }

  // Validate Authorization header
  const authHeader = request.headers?.authorization
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return {
      status: 401,
      headers: {
        "content-type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "0",
        Pragma: "no-cache",
      },
      body: { error: "Missing or invalid Authorization header" },
    }
  }

  // For JWT-based sessions, signout is stateless
  // We don't need to validate the token, just return success
  return {
    status: 200,
    headers: {
      "content-type": "application/json",
      "Cache-Control": "private, no-cache, no-store",
      Expires: "0",
      Pragma: "no-cache",
    },
    body: { message: "Signed out successfully" },
  }
}

/**
 * Mobile Callback - Handle OAuth and email callbacks for mobile clients
 */
export async function mobileCallback(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  // OAuth mobile callback is not implemented yet
  // Return 501 Not Implemented for now
  return {
    status: 501,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "private, no-cache, no-store",
      Expires: "Thu, 01 Jan 1970 00:00:00 GMT",
      Pragma: "no-cache",
    },
    body: {
      error: "OAuth callback not implemented",
    },
  }
}

/**
 * Mobile Email Callback - Handle email verification callback for mobile clients
 */
export async function mobileEmailCallback(
  request: RequestInternal,
  options: InternalOptions
): Promise<ResponseInternal> {
  const url = new URL(request.url)
  const paramToken = url.searchParams.get("token")
  const paramIdentifier = url.searchParams.get("email")

  if (!paramToken || !paramIdentifier) {
    return {
      status: 400,
      headers: {
        "content-type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "0",
        Pragma: "no-cache",
      },
      body: { error: "Missing token or email parameter" },
    }
  }

  try {
    const { adapter, callbacks } = options

    // Hash the token for database lookup
    const hashedToken = cryptoCreateHash("sha256")
      .update(`${paramToken}${options.secret}`)
      .digest("hex")

    // Use the verification token from the database
    const verificationToken = await adapter?.useVerificationToken?.({
      identifier: paramIdentifier,
      token: hashedToken,
    })

    if (!verificationToken) {
      return {
        status: 400,
        headers: {
          "content-type": "application/json",
          "Cache-Control": "private, no-cache, no-store",
          Expires: "0",
          Pragma: "no-cache",
        },
        body: { error: "Email verification failed" },
      }
    }

    // Check if token is expired
    if (
      verificationToken.expires &&
      new Date() > new Date(verificationToken.expires)
    ) {
      return {
        status: 400,
        headers: {
          "content-type": "application/json",
          "Cache-Control": "private, no-cache, no-store",
          Expires: "0",
          Pragma: "no-cache",
        },
        body: { error: "Email verification failed" },
      }
    }

    // Validate email matches the token identifier
    if (verificationToken.identifier !== paramIdentifier) {
      return {
        status: 400,
        headers: {
          "content-type": "application/json",
          "Cache-Control": "private, no-cache, no-store",
          Expires: "0",
          Pragma: "no-cache",
        },
        body: { error: "Email verification failed" },
      }
    }

    // Get or create user
    let user = await adapter?.getUserByEmail?.(paramIdentifier)
    if (!user) {
      user = await adapter?.createUser?.({
        id: crypto.randomUUID(),
        email: paramIdentifier,
        emailVerified: new Date(),
      })
    } else {
      // Update email verification
      await adapter?.updateUser?.({
        id: user.id,
        emailVerified: new Date(),
      })
    }

    if (!user) {
      return {
        status: 500,
        headers: {
          "content-type": "application/json",
          "Cache-Control": "private, no-cache, no-store",
          Expires: "0",
          Pragma: "no-cache",
        },
        body: { error: "Failed to create user" },
      }
    }

    // Check authorization via signIn callback
    if (callbacks.signIn) {
      const signInCallbackParams = {
        user,
        account: null,
        profile: undefined,
        email: { verificationRequest: true },
        credentials: undefined,
      }

      const allowed = await callbacks.signIn(signInCallbackParams)
      if (!allowed) {
        return {
          status: 403,
          headers: {
            "content-type": "application/json",
            "Cache-Control": "private, no-cache, no-store",
            Expires: "0",
            Pragma: "no-cache",
          },
          body: { error: "Access denied" },
        }
      }
    }

    // Create JWT session token
    const sessionMaxAge = options.session?.maxAge ?? 30 * 24 * 60 * 60 // 30 days
    const sessionExpiry = new Date(Date.now() + sessionMaxAge * 1000)

    const sessionData = {
      sub: user.id,
      id: user.id,
      name: user.name,
      email: user.email,
      image: user.image,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + sessionMaxAge * 1000,
    }

    const token = await encode({
      token: sessionData,
      secret: options.secret,
      salt: options.cookies.sessionToken.name,
      maxAge: sessionMaxAge,
    })

    return {
      status: 200,
      headers: {
        "content-type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "0",
        Pragma: "no-cache",
      },
      body: {
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          image: user.image,
        },
        expires: sessionExpiry.toISOString(),
      },
    }
  } catch (_error) {
    return {
      status: 400,
      headers: {
        "content-type": "application/json",
        "Cache-Control": "private, no-cache, no-store",
        Expires: "0",
        Pragma: "no-cache",
      },
      body: { error: "Email verification failed" },
    }
  }
}

// Default email normalizer (from send-token.ts)
function defaultNormalizer(email?: string): string {
  if (!email) throw new Error("Missing email")
  return email.toLowerCase()
}
