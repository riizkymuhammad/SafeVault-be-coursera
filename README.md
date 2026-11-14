# SafeVault

A learning sample that combines secure input validation, database access, authentication, role-based authorization, and regression tests for SQL injection and XSS.

## Stack

- ASP.NET Core 10 (LTS)
- ASP.NET Core Identity for password hashing and role storage
- EF Core with SQLite
- HMAC-SHA256 signed JWT access tokens
- xUnit and `WebApplicationFactory` integration tests

## Run locally

Install the .NET 10 SDK, then from this directory set a local signing key and run the API:

```bash
export Jwt__SigningKey='replace-this-with-a-random-secret-of-at-least-32-bytes'
export Jwt__Issuer='SafeVault'
export Jwt__Audience='SafeVaultClient'
dotnet run --project src/SafeVault.Api
```

The app creates `safevault.db` locally and initializes `User` and `Admin` roles. Registration assigns only the `User` role. For the learning sample, grant the `Admin` role through Identity's role manager or a controlled seed process; never expose self-service role assignment to ordinary users.

To create the first admin account on startup, provide both `BootstrapAdmin__Email` and `BootstrapAdmin__Password` through environment variables. The password must meet the configured Identity policy. Do not use this bootstrap setting as a permanent production provisioning mechanism.

## Run tests

```bash
dotnet test SafeVault.sln
```

The integration tests cover invalid registration, incorrect passwords, anonymous and non-admin access to the admin endpoint, admin access, SQL injection payloads in search, and HTML encoding of stored user content.

## Security choices

- **Input validation:** DTOs use Data Annotations for required fields, formats, and length limits. Search input is length-limited.
- **Password storage:** ASP.NET Core Identity hashes passwords; the application never stores or logs plaintext passwords.
- **SQL injection:** Search uses an EF Core expression with values passed as parameters. User input is not concatenated into SQL text.
- **Authentication:** Login checks the password through `SignInManager` and issues a short-lived signed token. Validation checks signature, issuer, audience, and expiration.
- **Authorization:** All record operations require authentication. Records are scoped to their owner; only the `Admin` role can open `/admin/dashboard` or search all users' records.
- **XSS:** The HTML search view encodes user-controlled content with `HtmlEncoder` before rendering it. JSON APIs should also be rendered with text APIs such as `textContent`, never `innerHTML` for untrusted strings.
- **Secrets:** Signing keys are read from environment configuration and are not committed. The sample refuses to start with a missing or short signing key.

## Vulnerability summary

| Risk | Fix | Regression test |
| --- | --- | --- |
| SQL injection from search text | EF Core parameterized query; no SQL string concatenation | `Search_SqlInjectionPayloadDoesNotReturnEveryRecord` |
| Stored/reflected XSS from record content | HTML encode untrusted text at the output boundary | `SearchView_HtmlEncodesUntrustedRecordContent` |
| Weak/invalid credentials | Identity password hashing, validation, and failed-login lockout | registration and invalid-login tests |
| Unauthorized admin access | JWT authentication and role-based policy | anonymous/user denied; admin allowed tests |
| Cross-user record access | Query scope uses authenticated subject ID | owner-scoped query in `/records/search` and `/records/search-view` |

## Copilot activity record

No Microsoft Copilot session was run while preparing this project in this workspace. Do not claim Copilot generated or debugged these files unless you actually review them with Copilot. Record the prompts and changes Copilot contributes in `SUBMISSION_SUMMARY.md` after that review.

## Before public deployment

This is an educational sample, not a production-ready financial system. Replace `EnsureCreated` with EF Core migrations, use a managed secrets store and production database, add rate limiting and security monitoring, configure HTTPS and a restrictive CORS policy, review token revocation/refresh requirements, and run dependency/security scans. Do not commit real customer records or secrets.
