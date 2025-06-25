/**
 * Manual Integration Test for Mobile Authentication Endpoints
 * 
 * This test can be run independently to verify mobile endpoints work correctly.
 * Run with: node test/actions/mobile-integration.test.js
 */

import { Auth } from "../../index.js"
import { encode } from "../../jwt.js"

const AUTH_SECRET = "test-secret-key-for-mobile-auth"
const SESSION_COOKIE_NAME = "__Secure-authjs.session-token"

// Test configuration
const testConfig = {
  secret: AUTH_SECRET,
  trustHost: true, // Allow any host for testing
  providers: [
    {
      id: "credentials",
      name: "Credentials",
      type: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      authorize: async (credentials) => {
        // Simple test auth - accept any email/password for testing
        if (credentials?.email && credentials?.password) {
          return {
            id: "1",
            email: credentials.email,
            name: "Test User"
          }
        }
        return null
      }
    }
  ],
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60 // 30 days
  },
  cookies: {
    sessionToken: {
      name: SESSION_COOKIE_NAME,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: true
      }
    }
  }
}

async function createTestRequest(action, options = {}) {
  const { method = "POST", headers = {}, body, path = "" } = options
  
  const url = `https://authjs.test/auth/${action}${path}`
  const requestHeaders = new Headers({
    "host": "authjs.test",
    "content-type": "application/json",
    ...headers
  })
  
  return new Request(url, {
    method,
    headers: requestHeaders,
    body: body ? JSON.stringify(body) : undefined
  })
}

async function testMobileSignIn() {
  console.log("\n🔐 Testing mobile-signin...")
  
  const request = await createTestRequest("mobile-signin/credentials", {
    body: {
      email: "test@example.com",
      password: "password123"
    }
  })
  
  try {
    const response = await Auth(request, testConfig)
    const status = response.status
    const contentType = response.headers.get("content-type")
    
    console.log(`   Status: ${status}`)
    console.log(`   Content-Type: ${contentType}`)
    
    if (status === 200) {
      const body = await response.json()
      console.log(`   ✅ Success! Token received: ${body.token ? "Yes" : "No"}`)
      console.log(`   Token length: ${body.token?.length || 0}`)
      console.log(`   Expires: ${body.expires}`)
      return body.token
    } else {
      const body = await response.json()
      console.log(`   ❌ Failed: ${body.error || "Unknown error"}`)
      return null
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`)
    return null
  }
}

async function testMobileSession(token) {
  console.log("\n🔄 Testing mobile-session...")
  
  if (!token) {
    console.log("   ⚠️  Skipping - no token from sign-in")
    return
  }
  
  const request = await createTestRequest("mobile-session", {
    method: "GET",
    headers: {
      authorization: `Bearer ${token}`
    }
  })
  
  try {
    const response = await Auth(request, testConfig)
    const status = response.status
    const contentType = response.headers.get("content-type")
    
    console.log(`   Status: ${status}`)
    console.log(`   Content-Type: ${contentType}`)
    
    if (status === 200) {
      const body = await response.json()
      console.log(`   ✅ Success! Session valid: ${body.session ? "Yes" : "No"}`)
      console.log(`   User email: ${body.session?.user?.email}`)
      console.log(`   New token: ${body.token ? "Yes" : "No"}`)
      console.log(`   New token length: ${body.token?.length || 0}`)
      return body.token
    } else {
      const body = await response.json()
      console.log(`   ❌ Failed: ${body.error || "Unknown error"}`)
      return null
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`)
    return null
  }
}

async function testMobileSignOut(token) {
  console.log("\n🚪 Testing mobile-signout...")
  
  if (!token) {
    console.log("   ⚠️  Skipping - no token available")
    return
  }
  
  const request = await createTestRequest("mobile-signout", {
    headers: {
      authorization: `Bearer ${token}`
    }
  })
  
  try {
    const response = await Auth(request, testConfig)
    const status = response.status
    const contentType = response.headers.get("content-type")
    
    console.log(`   Status: ${status}`)
    console.log(`   Content-Type: ${contentType}`)
    
    if (status === 200) {
      const body = await response.json()
      console.log(`   ✅ Success! ${body.message}`)
    } else {
      const body = await response.json()
      console.log(`   ❌ Failed: ${body.error || "Unknown error"}`)
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`)
  }
}

async function testInvalidToken() {
  console.log("\n🔒 Testing invalid token handling...")
  
  const request = await createTestRequest("mobile-session", {
    method: "GET",
    headers: {
      authorization: "Bearer invalid-token-12345"
    }
  })
  
  try {
    const response = await Auth(request, testConfig)
    const status = response.status
    
    console.log(`   Status: ${status}`)
    
    if (status === 401) {
      const body = await response.json()
      console.log(`   ✅ Correctly rejected invalid token: ${body.error}`)
    } else {
      console.log(`   ❌ Should have returned 401 for invalid token`)
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`)
  }
}

async function testMissingAuthHeader() {
  console.log("\n🚫 Testing missing Authorization header...")
  
  const request = await createTestRequest("mobile-session", {
    method: "GET"
  })
  
  try {
    const response = await Auth(request, testConfig)
    const status = response.status
    
    console.log(`   Status: ${status}`)
    
    if (status === 401) {
      const body = await response.json()
      console.log(`   ✅ Correctly rejected missing auth header: ${body.error}`)
    } else {
      console.log(`   ❌ Should have returned 401 for missing auth header`)
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`)
  }
}

async function runMobileEndpointTests() {
  console.log("🧪 Mobile Authentication Endpoints Integration Test")
  console.log("=" .repeat(60))
  
  try {
    // Test the full mobile auth flow
    const signInToken = await testMobileSignIn()
    const sessionToken = await testMobileSession(signInToken)
    await testMobileSignOut(sessionToken || signInToken)
    
    // Test error cases
    await testInvalidToken()
    await testMissingAuthHeader()
    
    console.log("\n" + "=" .repeat(60))
    console.log("🎉 Mobile endpoint tests completed!")
    console.log("Check the results above to verify functionality.")
    
  } catch (error) {
    console.error("\n❌ Test suite failed:", error.message)
    console.error(error.stack)
  }
}

// Run the tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runMobileEndpointTests()
}

export { runMobileEndpointTests }
