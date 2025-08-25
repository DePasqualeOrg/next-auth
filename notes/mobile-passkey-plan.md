# Mobile Passkey Authentication Implementation Plan

## Overview

This document outlines a comprehensive plan to implement Passkey (WebAuthn) authentication for mobile clients in Auth.js. The implementation leverages ~90% of the existing web-based WebAuthn infrastructure while adapting the challenge storage mechanism for mobile token-based authentication.

## Background

The existing Auth.js mobile authentication system provides:
- ✅ Credentials authentication
- ✅ Email authentication  
- ✅ JWT-based sessions
- ❌ **Missing**: WebAuthn/Passkey authentication

The web-based Passkey implementation provides robust WebAuthn support but uses cookie-based challenge storage, incompatible with mobile token-based authentication.

## Architecture Overview

### Current Web Passkey Flow
```
1. GET /webauthn-options/{providerId} → Generate options + challenge cookie
2. Client WebAuthn API call → Create credential/assertion
3. POST /callback/{providerId} → Verify response using challenge from cookie
4. Set session cookie → Authentication complete
```

### Proposed Mobile Passkey Flow  
```
1. POST /mobile-webauthn-options/{providerId} → Generate options + challenge token
2. Mobile WebAuthn API call → Create credential/assertion
3. POST /mobile-webauthn-callback/{providerId} → Verify response using challenge token
4. Return JWT token → Authentication complete
```

### Key Differences
- **Challenge Storage**: JWT tokens instead of cookies
- **Session Management**: JWT tokens instead of session cookies
- **API Format**: JSON responses instead of HTML forms
- **Core Logic**: **100% reused** from existing WebAuthn implementation

## Implementation Plan

## Phase 1: Foundation & Challenge Management

### Step 1.1: Mobile Challenge Token System
**Location**: `packages/core/src/lib/utils/mobile-webauthn-challenge.ts`

**Purpose**: Replace cookie-based challenge storage with JWT-based tokens

**Interface**:
```typescript
interface MobileChallengeData {
  challenge: string
  expires: number
  user?: User & { email: string } // For registration challenges
  action: "authenticate" | "register"
}

// Create secure challenge token (5-minute expiry)
export async function createMobileChallengeToken(
  challenge: string,
  options: InternalOptions,
  action: "authenticate" | "register", 
  user?: User & { email: string}
): Promise<string>

// Validate and extract challenge data
export async function validateMobileChallengeToken(
  token: string,
  options: InternalOptions
): Promise<MobileChallengeData>
```

**Security Features**:
- JWT signed with Auth.js secret
- 5-minute expiration window
- Action-specific validation
- User data embedded for registration flows

**Dependencies**: Existing JWT encode/decode functions

### Step 1.2: Mobile WebAuthn Wrapper Functions
**Location**: `packages/core/src/lib/utils/mobile-webauthn-utils.ts`

**Purpose**: Adapt existing WebAuthn option generation for mobile token-based flow

**Key Functions**:
```typescript
// Wrap existing getAuthenticationOptions with mobile challenge token
export async function getMobileAuthenticationResponse(
  options: InternalOptionsWebAuthn,
  request: RequestInternal,
  user?: User
): Promise<ResponseInternal>

// Wrap existing getRegistrationOptions with mobile challenge token  
export async function getMobileRegistrationResponse(
  options: InternalOptionsWebAuthn,
  request: RequestInternal,
  user: User & { email: string }
): Promise<ResponseInternal>
```

**Code Reuse**: 
- ✅ `getAuthenticationOptions()` - used as-is
- ✅ `getRegistrationOptions()` - used as-is
- 🔄 Challenge storage mechanism - adapted for mobile


**Dependencies**: Step 1.1, existing webauthn-utils functions

## Phase 2: Mobile Endpoints

### Step 2.1: Mobile WebAuthn Options Endpoint
**Location**: `packages/core/src/lib/actions/mobile/index.ts`

**Endpoint**: `GET/POST /mobile-webauthn-options/{providerId}`

**Purpose**: Generate WebAuthn options for mobile clients

**Request Parameters**:
```typescript
// Query parameters
{
  action?: "register" | "authenticate"  // Optional - will be inferred if not provided
  email?: string                        // Required for registration
  name?: string                         // Optional display name
}

// Headers  
{
  Authorization?: "Bearer <token>"      // Optional - for adding authenticators to existing accounts
}
```

**Response Format**:
```typescript
{
  action: "register" | "authenticate",
  options: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON,
  challengeToken: string,               // JWT token containing challenge data
  callbackUrl: string                   // URL for submitting WebAuthn response
}
```

**Core Logic Reuse**:
- ✅ `assertInternalOptionsWebAuthn()` - Provider validation
- ✅ `inferWebAuthnOptions()` - Action decision logic  
- ✅ `getUserInfo()` - User information resolution
- ✅ `getAuthenticationOptions()` / `getRegistrationOptions()` - Options generation
  **Dependencies**: Phase 1, existing webauthn-utils

### Step 2.2: Mobile WebAuthn Callback Endpoint  
**Location**: `packages/core/src/lib/actions/mobile/index.ts`

**Endpoint**: `POST /mobile-webauthn-callback/{providerId}`

**Purpose**: Verify WebAuthn responses and return JWT tokens

**Request Format**:
```typescript
{
  challengeToken: string,               // Token from options endpoint
  action: "register" | "authenticate",
  data: AuthenticationResponseJSON | RegistrationResponseJSON
}
```

**Response Format**:
```typescript
// Success
{
  token: string,                        // JWT session token
  user: {
    id: string,
    email: string,
    name?: string,
    image?: string
  },
  expires: string                       // ISO timestamp
}

// Error
{
  error: string
}
```

**Core Logic Reuse**:
- ✅ `verifyAuthenticate()` - Complete authentication verification
- ✅ `verifyRegister()` - Complete registration verification
- ✅ Database operations - All adapter methods used as-is
- 🔄 Challenge validation - Adapted from cookies to JWT tokens
- 🔄 Response format - JWT instead of session cookies

**Dependencies**: Phase 1, Step 2.1, existing verification functions

## Phase 3: Integration & Routing

### Step 3.1: WebAuthn Provider Support in Mobile SignIn
**Location**: `packages/core/src/lib/actions/mobile/index.ts` (modify existing `mobileSignIn`)

**Purpose**: Handle WebAuthn providers in mobile authentication flow

**Implementation**:
```typescript
// Add to existing mobileSignIn function
if (provider.type === "webauthn") {
  return {
    status: 200,
    headers: { "Content-Type": "application/json", ...securityHeaders },
    body: {
      action: "webauthn",
      optionsUrl: `${options.url}/mobile-webauthn-options/${provider.id}`,
      callbackUrl: `${options.url}/mobile-webauthn-callback/${provider.id}`,
      provider: provider.id,
    },
  }
}
```

**Client Flow**:
1. Client calls `/mobile-signin` with `providerId: "passkey"`
2. Server returns WebAuthn endpoint URLs
3. Client proceeds with WebAuthn flow


**Dependencies**: Existing mobile signin function

### Step 3.2: Action Registration
**Location**: `packages/core/src/lib/utils/actions.ts`

**Purpose**: Register new mobile WebAuthn actions

**Implementation**:
```typescript
const actions: AuthAction[] = [
  // ... existing actions
  "mobile-webauthn-options",
  "mobile-webauthn-callback",
]
```


**Dependencies**: None

### Step 3.3: Route Handler Integration  
**Location**: `packages/core/src/lib/index.ts` (modify `AuthInternal`)

**Purpose**: Route mobile WebAuthn requests to appropriate handlers

**Implementation**:
```typescript
// Add to GET method handlers
case "mobile-webauthn-options":
  return await mobileActions.mobileWebAuthnOptions(request, options)

// Add to POST method handlers  
case "mobile-webauthn-callback":
  return await mobileActions.mobileWebAuthnCallback(request, options)
```


**Dependencies**: Phase 2 endpoints

## Phase 4: Testing & Validation

### Step 4.1: Unit Tests
**Location**: `packages/core/test/actions/mobile-webauthn.test.ts`

**Test Coverage**:

**Challenge Token System**:
- ✅ Token creation and validation
- ✅ Expiration handling
- ✅ Invalid token rejection
- ✅ Action mismatch detection

**Options Generation**:
- ✅ Authentication options with valid user
- ✅ Registration options with new user
- ✅ Registration options for existing user adding authenticator
- ✅ Error handling for invalid requests

**Callback Verification**:
- ✅ Successful authentication verification
- ✅ Successful registration verification  
- ✅ Invalid response rejection
- ✅ Expired challenge handling
- ✅ Database integration (create user, link account, store authenticator)

**Integration**:
- ✅ Mobile signin WebAuthn provider handling
- ✅ End-to-end flow simulation
- ✅ JWT token generation and validation

**Mock Strategy**:
```typescript
// Mock SimpleWebAuthn functions to return controlled verification results
const mockVerifyAuthentication = vi.fn().mockResolvedValue({
  verified: true,
  authenticationInfo: { newCounter: 1 }
})

// Mock adapter functions for database operations
const mockAdapter = {
  getAuthenticator: vi.fn(),
  updateAuthenticatorCounter: vi.fn(),
  getAccount: vi.fn(),
  getUser: vi.fn(),
  createUser: vi.fn(),
  linkAccount: vi.fn(),
  createAuthenticator: vi.fn(),
}
```


**Dependencies**: All previous phases

### Step 4.2: Integration Tests
**Location**: `packages/core/test/integration/mobile-webauthn.test.ts`

**Test Scenarios**:

**End-to-End Authentication**:
1. Generate authentication options
2. Simulate WebAuthn API response
3. Verify callback processes correctly
4. Validate JWT token returned

**End-to-End Registration**:
1. Generate registration options for new user
2. Simulate WebAuthn credential creation
3. Verify user creation and authenticator storage
4. Validate JWT token for new user

**Multi-Authenticator Registration**:
1. Authenticate existing user
2. Generate registration options for additional authenticator
3. Verify new authenticator added to existing account

**Error Scenarios**:
- Invalid challenge tokens
- Expired challenges
- Malformed WebAuthn responses
- Database operation failures


**Dependencies**: Step 4.1

## Phase 5: Documentation & Examples

### Step 5.1: API Documentation
**Location**: Update mobile authentication documentation

**Content Structure**:

**Mobile WebAuthn Flow Overview**:
- Architecture diagram
- Sequence diagrams for registration and authentication
- Comparison with web-based flow

**API Reference**:
- `/mobile-webauthn-options/{providerId}` endpoint specification
- `/mobile-webauthn-callback/{providerId}` endpoint specification  
- Request/response examples
- Error codes and descriptions

**Security Considerations**:
- Challenge token security model
- Mobile origin validation requirements
- Relying Party configuration for mobile apps



### Step 5.2: Client Implementation Examples
**Location**: Create example mobile app integrations

**React Native Example**:
```typescript
// Example WebAuthn registration flow
async function registerPasskey() {
  // 1. Get options from server
  const optionsResponse = await fetch('/api/auth/mobile-webauthn-options/passkey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com', action: 'register' })
  });
  const { options, challengeToken, callbackUrl } = await optionsResponse.json();
  
  // 2. Use platform WebAuthn API
  const credential = await PublicKeyCredential.create({ publicKey: options });
  
  // 3. Submit response
  const authResponse = await fetch(callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challengeToken,
      action: 'register',
      data: credential.response
    })
  });
  const { token, user } = await authResponse.json();
  
  // 4. Store JWT token for subsequent requests
  await AsyncStorage.setItem('auth-token', token);
}
```

**iOS Swift Example**:
```swift
import AuthenticationServices

// Example WebAuthn authentication flow
func authenticateWithPasskey() {
    // 1. Get options from server
    let optionsRequest = // ... API call to mobile-webauthn-options
    
    // 2. Create ASAuthorization request
    let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
    let request = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: options.challenge)
    
    // 3. Present authorization UI
    let authController = ASAuthorizationController(authorizationRequests: [request])
    authController.delegate = self
    authController.presentationContextProvider = self
    authController.performRequests()
}

// Handle WebAuthn response
func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    // Submit response to mobile-webauthn-callback
    // Store returned JWT token
}
```

**Android Kotlin Example**:
```kotlin
// Example using FIDO2 API
class PasskeyManager {
    fun authenticateWithPasskey() {
        // 1. Get options from server
        val options = // ... API call to mobile-webauthn-options
        
        // 2. Create FIDO2 API request
        val fido2ApiClient = Fido.getFido2ApiClient(activity)
        val task = fido2ApiClient.getSignPendingIntent(
            PublicKeyCredentialRequestOptions.Builder()
                .setChallenge(options.challenge)
                .setRpId(options.rpId)
                .setAllowCredentials(options.allowCredentials)
                .build()
        )
        
        // 3. Handle response
        task.addOnSuccessListener { result ->
            // Submit response to mobile-webauthn-callback
            // Store returned JWT token
        }
    }
}
```



## Risk Assessment

### Low Risk ✅
- **Code Reuse**: 90% of WebAuthn logic already exists and tested
- **Architecture Fit**: JWT-based tokens align with existing mobile auth system
- **Security Model**: Using proven JWT infrastructure for challenge storage

### Medium Risk ⚠️
- **Mobile Platform Differences**: WebAuthn API variations across iOS/Android
  - *Mitigation*: Comprehensive cross-platform testing
  - *Fallback*: Platform-specific documentation and examples

- **Mobile Origin Validation**: App-based origins vs web origins
  - *Mitigation*: Start with basic implementation, enhance iteratively
  - *Research*: Review WebAuthn spec for mobile app origin handling

### Minimal Risk 🟢
- **Challenge Token Security**: Reusing existing JWT infrastructure
- **Database Integration**: All adapter methods already exist
- **Performance Impact**: Minimal - mostly wrapping existing functions

## Success Criteria

### Functional Requirements ✅
1. **Registration Flow**: Mobile apps can register new Passkey authenticators
2. **Authentication Flow**: Mobile apps can authenticate with existing Passkeys
3. **Multi-Authenticator Support**: Users can register multiple Passkeys per account  
4. **JWT Integration**: Successful authentication returns valid JWT tokens
5. **Error Handling**: Comprehensive error responses for all failure scenarios

### Technical Requirements ✅
1. **Provider Compatibility**: Full compatibility with existing WebAuthn provider configuration
2. **Security Standards**: Maintains WebAuthn security properties (challenge uniqueness, expiration, etc.)
3. **Performance**: Response times comparable to other mobile auth endpoints
4. **Code Quality**: 90%+ test coverage, comprehensive error handling

### Integration Requirements ✅
1. **Mobile Auth System**: Seamless integration with existing mobile endpoints
2. **Database Compatibility**: Works with all existing Auth.js database adapters
3. **Configuration**: Minimal configuration changes required
4. **Backward Compatibility**: No breaking changes to existing functionality

## Post-Implementation Enhancements

### Phase 6: Advanced Features (Future)
- **Conditional UI Support**: Mobile equivalent of web conditional UI
- **Biometric Prompt Customization**: Platform-specific biometric prompts
- **Device Attestation**: Enhanced security through mobile device attestation
- **Cross-Device Authentication**: QR code flows for cross-device scenarios

### Phase 7: Platform Optimizations (Future)
- **iOS-Specific Features**: Integration with iOS Keychain, App Clip support
- **Android-Specific Features**: Integration with Android Keystore, Play Integrity
- **React Native Package**: Dedicated React Native wrapper package
- **Flutter Package**: Dedicated Flutter wrapper package
