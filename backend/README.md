
# Final API Flow

## 🔁 Every Request — JwtFilter (runs before all controllers)

```
Browser sends any request
    │
    ▼
JwtFilter.doFilterInternal()
    │
    ├── Read "accessToken" from cookie
    │
    ├── No cookie found?
    │   └── Skip auth → continue to SecurityConfig rules
    │
    └── Cookie found?
        ├── Extract email from JWT subject
        ├── Load UserDetails from DB (CustomerUserDetailsService)
        ├── Validate JWT (signature + expiry + email match)
        │
        ├── ✅ Valid  → Set Authentication in SecurityContext
        └── ❌ Invalid → Skip auth, continue unauthenticated
                │
                ▼
    SecurityConfig decides: permitAll? authenticated? hasRole("ADMIN")?
        │
        ├── Allowed → Controller handles the request
        └── Denied  → 401 {"success":false,"message":"Unauthorized","data":null}
```

---

## 1️⃣ POST `/api/auth/register` — Public

```
Client sends:
{
    "username": "john",
    "email": "john@mail.com",
    "password": "123456",
    "confirmPassword": "123456"
}
    │
    ▼
AuthController.register(@Valid @RequestBody)
    │
    ▼
AuthServiceImpl.register()
    ├── Email already exists?        → 400 "Email is already registered"
    ├── password ≠ confirmPassword?  → 400 "Passwords do not match"
    ├── Find "USER" role from DB     → 500 "Default role USER not found"
    ├── Create User (hash password with BCrypt)
    ├── Save to DB
    └── Return 201:
        {
            "success": true,
            "message": "Registration successful",
            "data": { "id": 1, "username": "john", "email": "john@mail.com", "roles": ["USER"] },
            "timestamp": "2026-02-24T..."
        }
```

---

## 2️⃣ POST `/api/auth/login` — Public

```
Client sends:
{
    "email": "john@mail.com",
    "password": "123456"
}
    │
    ▼
AuthController.login(@Valid @RequestBody)
    │
    ▼
AuthServiceImpl.login()
    ├── AuthenticationManager.authenticate()
    │   └── DaoAuthenticationProvider
    │       └── CustomerUserDetailsService.loadUserByUsername(email)
    │           └── BCrypt compares password
    │           └── ❌ Wrong → 401 "Invalid email or password"
    │
    ├── ✅ Authenticated
    ├── Find user from DB
    ├── Generate accessToken JWT   (10 min, contains uid + roles)
    ├── Generate refreshToken JWT  (2 hours)
    ├── Delete all old refresh tokens for this user
    ├── Save new RefreshToken to DB (token, user, revoked=false, expiresAt)
    ├── Set HttpOnly cookies: "accessToken" + "refreshToken"
    └── Return 200:
        {
            "success": true,
            "message": "Login successful",
            "data": {
                "access_token": "eyJ...",
                "refresh_token": "eyJ...",
                "type": "Bearer",
                "roles": ["USER"]
            },
            "timestamp": "2026-02-24T..."
        }

    Cookies set:
    ┌──────────────────────────────────────────────┐
    │ accessToken=eyJ...;  HttpOnly; Secure; 10min │
    │ refreshToken=eyJ...; HttpOnly; Secure; 2h    │
    └──────────────────────────────────────────────┘
```

---

## 3️⃣ GET `/api/auth/me` — Authenticated

```
Browser sends request (accessToken cookie auto-attached)
    │
    ▼
JwtFilter → validates accessToken → sets SecurityContext
    │
    ▼
AuthController.me(authentication)
    │
    ▼
AuthServiceImpl.me()
    ├── Not authenticated?  → 401 "Not authenticated"
    ├── Read email from Authentication.getName()
    ├── Find user by email  → 404 "User not found"
    └── Return 200:
        {
            "success": true,
            "message": "User info retrieved",
            "data": {
                "username": "john",
                "email": "john@mail.com",
                "photo": null,
                "phoneNumber": null,
                "address": null,
                "bio": null,
                "roles": ["USER"]
            },
            "timestamp": "2026-02-24T..."
        }
```

---

## 4️⃣ PUT `/api/auth/profile` — Authenticated

```
Browser sends (accessToken cookie auto-attached):
{
    "username": "John Updated",
    "phoneNumber": "012345678",
    "address": "Phnom Penh",
    "bio": "I am a developer",
    "photo": "https://example.com/photo.jpg"
}
    │
    ▼  (all fields are optional — only send what you want to change)
    │
JwtFilter → validates accessToken → sets SecurityContext
    │
    ▼
AuthController.updateProfile(authentication, @Valid @RequestBody)
    │
    ▼
AuthServiceImpl.updateProfile()
    ├── Not authenticated?  → 401 "Not authenticated"
    ├── Read email from JWT (Authentication.getName())
    ├── Find user by email  → 404 "User not found"
    ├── Update only non-null fields:
    │   ├── username?    → user.setUsername()
    │   ├── phoneNumber? → user.setPhoneNumber()
    │   ├── address?     → user.setAddress()
    │   ├── bio?         → user.setBio()
    │   └── photo?       → user.setPhoto()
    ├── Save to DB
    └── Return 200:
        {
            "success": true,
            "message": "Profile updated successfully",
            "data": {
                "username": "John Updated",
                "email": "john@mail.com",
                "photo": "https://example.com/photo.jpg",
                "phoneNumber": "012345678",
                "address": "Phnom Penh",
                "bio": "I am a developer",
                "roles": ["USER"]
            },
            "timestamp": "2026-02-24T..."
        }
```

---

## 5️⃣ POST `/api/auth/refresh` — Public

```
Browser sends request (refreshToken cookie auto-attached)
    │
    ▼
AuthController.refresh(@CookieValue refreshToken)
    │
    ▼
AuthServiceImpl.refresh()
    ├── No refreshToken cookie?        → 401 "Refresh token missing"
    │
    ├── RefreshTokenService.verify()
    │   ├── Token not in DB?           → 401 "Invalid refresh token"
    │   ├── Token revoked?             → 401 "Refresh token revoked"
    │   └── Token expiresAt passed?    → 401 "Refresh token expired"
    │
    ├── JwtService.validateRefreshToken()
    │   ├── JWT signature invalid?     → 401 "Invalid refresh token"
    │   ├── JWT expired?               → 401
    │   ├── Token not in DB?           → 401
    │   ├── Token revoked?             → 401
    │   └── Username mismatch?         → 401
    │
    ├── ✅ All passed
    ├── Generate new accessToken
    ├── Overwrite "accessToken" cookie
    └── Return 200:
        {
            "success": true,
            "message": "Token refreshed",
            "data": null,
            "timestamp": "2026-02-24T..."
        }

    Cookie updated:
    ┌──────────────────────────────────────────────────┐
    │ accessToken=NEW_eyJ...; HttpOnly; Secure; 10min  │
    └──────────────────────────────────────────────────┘
```

---

## 6️⃣ POST `/api/auth/logout` — Public

```
Browser sends request (refreshToken cookie auto-attached)
    │
    ▼
AuthController.logout(@CookieValue refreshToken)
    │
    ▼
AuthServiceImpl.logout()
    ├── If refreshToken exists → mark revoked=true in DB
    ├── Clear "accessToken" cookie  (Max-Age=0)
    ├── Clear "refreshToken" cookie (Max-Age=0)
    └── Return 200:
        {
            "success": true,
            "message": "Logged out successfully",
            "data": null,
            "timestamp": "2026-02-24T..."
        }

    Cookies cleared:
    ┌─────────────────────────────────────────┐
    │ accessToken=;  Max-Age=0  (deleted)     │
    │ refreshToken=; Max-Age=0  (deleted)     │
    └─────────────────────────────────────────┘
```

---

## 🔐 SecurityConfig Route Map

| Route | Method | Access |
|-------|--------|--------|
| `OPTIONS /**` | OPTIONS | permitAll |
| `/error` | * | permitAll |
| `/api/auth/me` | GET | 🔒 authenticated |
| `/api/auth/profile` | PUT | 🔒 authenticated |
| `/api/auth/register` | POST | permitAll |
| `/api/auth/login` | POST | permitAll |
| `/api/auth/refresh` | POST | permitAll |
| `/api/auth/logout` | POST | permitAll |
| `/api/users/register` | POST | permitAll |
| `/api/products/dashboard` | GET | 🔒 ADMIN |
| `/api/products/**` | POST/PUT/DELETE | 🔒 ADMIN |
| `/api/products/**` | GET | permitAll |
| `/api/categories/**` | POST/PUT/DELETE | 🔒 ADMIN |
| `/api/categories/**` | GET | permitAll |
| `/api/users/**` | GET | 🔒 ADMIN |
| `/dashboard` | * | 🔒 ADMIN |
| `/api/admin/**` | * | 🔒 ADMIN |
| Everything else | * | 🔒 authenticated |

---

## 🔄 Token Lifecycle

```
 ┌─────────┐
 │ REGISTER │ ──→ User created in DB (no tokens)
 └─────────┘
      │
      ▼
 ┌─────────┐     accessToken cookie (10 min)
 │  LOGIN   │ ──→ refreshToken cookie (2 hours)
 └─────────┘     RefreshToken saved to DB (old ones deleted)
      │
      ├──── Every request: JwtFilter reads accessToken cookie
      │
      ├──── Access expired? → POST /refresh
      │         │
      │         └──→ Verify refreshToken (DB + JWT)
      │              Issue new accessToken cookie
      │
      ├──── Need profile? → GET /me
      │
      ├──── Edit profile? → PUT /profile (partial update)
      │
      └──── Done? → POST /logout
                │
                └──→ Revoke refreshToken in DB
                     Clear both cookies
```

---

## 📁 File Structure

```
controller/
  └── AuthController.java          ← HTTP layer (6 endpoints)

service/
  ├── AuthService.java             ← Interface
  ├── JwtService.java              ← Interface
  ├── RefreshTokenService.java     ← Interface
  └── impl/
      ├── AuthServiceImpl.java     ← Business logic (register, login, me, profile, refresh, logout)
      ├── JwtServiceImpl.java      ← JWT generate, parse, validate
      └── RefreshTokenServiceImpl.java ← DB verify + revoke

request/
  ├── RegisterRequest.java         ← { username, email, password, confirmPassword }
  ├── AuthLoginRequest.java        ← { email, password }
  └── UpdateProfileRequest.java    ← { username?, phoneNumber?, address?, bio?, photo? }

response/
  ├── ApiResponse.java             ← Wrapper: { success, message, data, timestamp }
  ├── AuthResponse.java            ← { access_token, refresh_token, type, roles }
  ├── RegisterResponse.java        ← { id, username, email, roles }
  └── MeResponse.java              ← { username, email, photo, phoneNumber, address, bio, roles }

model/
  ├── User.java                    ← Entity (id, username, email, password, enable, phone, address, bio, photo, roles)
  ├── Role.java                    ← Entity (id, name)
  └── RefreshToken.java            ← Entity (id, token, user, revoked, expiresAt)

config/
  ├── SecurityConfig.java          ← Route rules, CORS, stateless session, JWT filter
  ├── JwtFilter.java               ← Reads accessToken cookie → sets SecurityContext
  └── JwtProperties.java           ← jwt.secret, expiration (10min), refreshExpiration (2h)

exception/
  └── GlobalExceptionHandler.java  ← Catches all exceptions → consistent ApiResponse format

util/
  └── CookieUtil.java              ← addCookie / clearCookie (HttpOnly, Secure, SameSite=None)
```
