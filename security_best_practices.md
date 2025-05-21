# Security Best Practices for Next Auth Kit

This guide outlines security best practices to follow when implementing Next Auth Kit in your application.

## Table of Contents

1. [Secret Management](#secret-management)
2. [Cookie Security](#cookie-security)
3. [Password Security](#password-security)
4. [HTTPS](#https)
5. [CSRF Protection](#csrf-protection)
6. [API Rate Limiting](#api-rate-limiting)
7. [Error Handling](#error-handling)
8. [Session Management](#session-management)
9. [OAuth Security](#oauth-security)
10. [Database Security](#database-security)
11. [Monitoring and Logging](#monitoring-and-logging)
12. [Security Headers](#security-headers)

## Secret Management

### Recommendations

- **Never commit secrets to version control**: Use environment variables to store secrets and sensitive information.
- **Use a secret with high entropy**: Your `AUTH_SECRET` should be at least 32 characters long and randomly generated.
- **Rotate secrets regularly**: Periodically change secrets, especially after team member changes.
- **Use a secret manager**: Consider using AWS Secrets Manager, Google Secret Manager, or HashiCorp Vault in production.

### Implementation

```bash
# Generate a strong random secret
openssl rand -base64 32
```

```env
# .env
AUTH_SECRET="your-randomly-generated-secret"
```

```typescript
// lib/auth.ts
export const authConfig = defineConfig({
  secret: process.env.AUTH_SECRET,
  // Other configuration...
});
```

## Cookie Security

### Recommendations

- **Use HTTP-only cookies**: This prevents JavaScript from accessing cookies, mitigating XSS attacks.
- **Enable secure flag in production**: Ensure cookies are only sent over HTTPS.
- **Set appropriate domain scoping**: Be specific about which domains can receive cookies.
- **Implement proper expiration**: Balance security and user experience with reasonable session lengths.
- **Use SameSite policy**: Implement appropriate SameSite cookie settings.

### Implementation

Next Auth Kit sets these by default, but ensure your configuration enables secure cookies in production:

```typescript
// lib/auth.ts
export const authConfig = defineConfig({
  secureCookies: process.env.NODE_ENV === 'production',
  cookieMaxAge: 14 * 24 * 60 * 60, // 14 days in seconds
  // Other configuration...
});
```

## Password Security

### Recommendations

- **Enforce strong password requirements**: Require passwords to be at least 12 characters and include a mix of character types.
- **Use a proper password hashing algorithm**: Next Auth Kit uses bcrypt for password hashing.
- **Implement account lockout mechanisms**: Consider locking accounts after multiple failed login attempts.
- **Add password breach detection**: Check passwords against known breached password databases.
- **Encourage password managers**: Design your UI to be compatible with password managers.

### Implementation

Customize the password validation in your form:

```tsx
// Enhanced password validation
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{12,}$/;

// In your registration form
if (!passwordRegex.test(password)) {
  setError("Password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters");
  return;
}
```

You can also implement password breach detection using an API like "Have I Been Pwned":

```typescript
async function isPasswordBreached(password: string): Promise<boolean> {
  // Using the Have I Been Pwned API's k-anonymity model
  const sha1Password = createSHA1Hash(password);
  const prefix = sha1Password.substring(0, 5);
  const suffix = sha1Password.substring(5).toUpperCase();
  
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await response.text();
  
  // Check if the suffix appears in the response
  return text.includes(suffix);
}
```

## HTTPS

### Recommendations

- **Always use HTTPS in production**: Never transmit sensitive information over unencrypted connections.
- **Implement HSTS**: Use HTTP Strict Transport Security to ensure all traffic uses HTTPS.
- **Redirect HTTP to HTTPS**: Automatically redirect any HTTP requests to HTTPS.
- **Keep certificates up to date**: Use automated services like Let's Encrypt to manage certificates.

### Implementation

For Next.js applications, most of these recommendations are implemented at the hosting level. For example, Vercel handles HTTPS and certificate management automatically.

For custom server deployments, update your server configuration:

```javascript
// server.js for custom Next.js server
const { createServer } = require('https');
const { parse } = require('url');
const next = require('next');
const fs = require('fs');

const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();

const httpsOptions = {
  key: fs.readFileSync('./certificates/key.pem'),
  cert: fs.readFileSync('./certificates/cert.pem')
};

app.prepare().then(() => {
  createServer(httpsOptions, (req, res) => {
    const parsedUrl = parse(req.url, true);
    handle(req, res, parsedUrl);
  }).listen(3000, (err) => {
    if (err) throw err;
    console.log('> Ready on https://localhost:3000');
  });
});
```

## CSRF Protection

### Recommendations

- **Use anti-CSRF tokens**: Implement token-based CSRF protection for sensitive operations.
- **Check the Referer header**: Validate that sensitive requests are coming from your application.
- **Implement SameSite cookies**: Use 'strict' or 'lax' SameSite cookie attribute.
- **Validate state in OAuth flows**: Ensure the state parameter is validated in OAuth callbacks.

### Implementation

Next Auth Kit includes CSRF protection in its OAuth flows, but you can add additional protection for sensitive operations:

```typescript
// Generate a CSRF token
function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Store token in session
async function storeCSRFToken(token: string): Promise<void> {
  // Store in server-side session or secure cookie
}

// Verify token
function verifyCSRFToken(storedToken: string, receivedToken: string): boolean {
  // Use constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(storedToken, 'hex'),
    Buffer.from(receivedToken, 'hex')
  );
}
```

Include this token in your forms:

```tsx
<form onSubmit={handleSubmit}>
  <input type="hidden" name="csrf_token" value={csrfToken} />
  {/* Other form fields */}
</form>
```

## API Rate Limiting

### Recommendations

- **Implement rate limiting**: Limit the number of requests from a single IP or user account.
- **Consider different limits by endpoint**: Apply stricter limits to authentication endpoints.
- **Add progressive delays**: Increase delay times after consecutive failures.
- **Monitor and alert on suspicious activity**: Be notified of potential brute force attempts.

### Implementation

Add rate limiting middleware to your authentication API routes:

```typescript
// lib/rate-limit.ts
import { NextRequest, NextResponse } from 'next/server';
import { redis } from './redis'; // Your Redis client

export async function rateLimit(
  req: NextRequest,
  identifier: string,
  limit: number,
  window: number
): Promise<{ success: boolean; limit: number; remaining: number }> {
  const key = `rate-limit:${identifier}`;
  const current = await redis.incr(key);
  
  // Set expiry on first request
  if (current === 1) {
    await redis.expire(key, window);
  }
  
  return {
    success: current <= limit,
    limit,
    remaining: Math.max(0, limit - current)
  };
}
```

Apply it to your auth routes:

```typescript
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { loginHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';
import { rateLimit } from '@/lib/rate-limit';

export async function POST(req: NextRequest) {
  // Get client IP or session identifier
  const identifier = req.headers.get('x-forwarded-for') || 'unknown';
  
  // 10 requests per minute
  const { success, limit, remaining } = await rateLimit(req, identifier, 10, 60);
  
  if (!success) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { 
        status: 429,
        headers: {
          'X-RateLimit-Limit': limit.toString(),
          'X-RateLimit-Remaining': remaining.toString(),
          'Retry-After': '60'
        }
      }
    );
  }
  
  return loginHandler(req, authConfig, prisma);
}
```

## Error Handling

### Recommendations

- **Provide generic error messages**: Don't expose sensitive information in error messages.
- **Log detailed errors server-side**: Keep detailed logs for debugging but don't expose them to users.
- **Implement graceful fallbacks**: Always provide a user-friendly fallback when errors occur.
- **Don't leak information**: Avoid revealing whether a username exists during login failures.

### Implementation

Instead of:

```tsx
// Bad practice
if (!user) {
  return NextResponse.json(
    { error: 'User not found' },
    { status: 404 }
  );
}
```

Use:

```tsx
// Good practice
if (!user) {
  // Log detailed error server-side
  console.error(`Login attempt failed for email: ${email}`);
  
  // Return generic message to user
  return NextResponse.json(
    { error: 'Invalid email or password' },
    { status: 401 }
  );
}
```

## Session Management

### Recommendations

- **Implement secure session storage**: Use HTTP-only cookies for session tokens.
- **Short session durations**: Set reasonably short session durations (e.g., 14 days).
- **Periodic revalidation**: Validate sessions periodically even if they haven't expired.
- **Provide logout functionality**: Always include a clear way for users to log out.
- **Invalidate sessions on security events**: Log users out when they change passwords.

### Implementation

Configure appropriate session duration:

```typescript
// lib/auth.ts
export const authConfig = defineConfig({
  cookieMaxAge: 14 * 24 * 60 * 60, // 14 days in seconds
  // Other configuration...
});
```

Implement session invalidation on password change:

```typescript
async function changePassword(userId: string, newPassword: string) {
  // Hash the new password
  const hashedPassword = await bcrypt.hash(newPassword, 12);
  
  // Update the password
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword }
  });
  
  // Invalidate all sessions
  await prisma.session.deleteMany({
    where: { userId }
  });
}
```

## OAuth Security

### Recommendations

- **Verify OAuth redirects**: Only allow redirects to trusted domains.
- **Validate state parameter**: Always validate the state parameter in OAuth callbacks.
- **Keep client secrets secure**: Never expose OAuth client secrets to clients.
- **Verify email ownership**: Require email verification for OAuth sign-ups.
- **Scope permissions appropriately**: Request only the permissions your app needs.

### Implementation

Next Auth Kit implements most of these recommendations by default. Ensure you're using the built-in OAuth handlers:

```typescript
// app/api/auth/[provider]/route.ts
export async function GET(
  req: NextRequest,
  { params }: { params: { provider: string } }
) {
  const provider = getProviderById(authConfig.providers, params.provider);
  
  if (!provider) {
    return NextResponse.json(
      { error: 'Provider not found' },
      { status: 404 }
    );
  }
  
  return oauthAuthorizeHandler(req, authConfig, provider);
}
```

## Database Security

### Recommendations

- **Use prepared statements**: Avoid SQL injection by using parameterized queries.
- **Implement least privilege**: Database users should have minimal required permissions.
- **Encrypt sensitive data**: Consider field-level encryption for particularly sensitive data.
- **Regular backups**: Implement regular database backups with encryption.
- **Database firewalls**: Restrict database access to specific IP addresses.

### Implementation

Next Auth Kit uses Prisma, which provides protection against SQL injection by default. For field-level encryption:

```typescript
// lib/encryption.ts
import crypto from 'crypto';

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const IV_LENGTH = 16;

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

export function decrypt(text: string): string {
  const [ivHex, encryptedHex] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
```

## Monitoring and Logging

### Recommendations

- **Log authentication events**: Record successful and failed authentication attempts.
- **Monitor for unusual activity**: Set up alerts for suspicious login patterns.
- **Implement audit trails**: Track security-relevant actions.
- **Use structured logging**: Ensure logs are machine-readable and searchable.
- **Maintain log security**: Secure access to logs and remove sensitive information.

### Implementation

Create a secure logging wrapper:

```typescript
// lib/secure-logger.ts
interface LogData {
  event: string;
  userId?: string;
  metadata?: Record<string, any>;
  [key: string]: any;
}

export function secureLog(data: LogData): void {
  // Remove sensitive fields
  const sanitizedData = { ...data };
  const sensitiveFields = ['password', 'token', 'secret'];
  
  for (const field of sensitiveFields) {
    if (sanitizedData[field]) {
      sanitizedData[field] = '[REDACTED]';
    }
  }
  
  // Add timestamp and other context
  const logEntry = {
    ...sanitizedData,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
  };
  
  // Log to your preferred destination
  console.log(JSON.stringify(logEntry));
  
  // In production, you'd send this to a logging service
  // logstashClient.send(logEntry);
}
```

Use it in your authentication handlers:

```typescript
// When a user logs in
secureLog({
  event: 'user.login',
  userId: user.id,
  metadata: {
    ip: req.headers.get('x-forwarded-for') || 'unknown',
    userAgent: req.headers.get('user-agent') || 'unknown',
    success: true
  }
});

// Failed login attempt
secureLog({
  event: 'user.login.failed',
  metadata: {
    email: attemptedEmail, // Only log this if you need it for security monitoring
    ip: req.headers.get('x-forwarded-for') || 'unknown',
    userAgent: req.headers.get('user-agent') || 'unknown',
    reason: 'invalid_credentials'
  }
});
```

## Security Headers

### Recommendations

- **Implement Content Security Policy (CSP)**: Prevent XSS attacks by defining allowed content sources.
- **Use HSTS headers**: Force browsers to use HTTPS for your domain.
- **Enable X-XSS-Protection**: Activate browser's built-in XSS filters.
- **Set X-Content-Type-Options**: Prevent MIME type sniffing attacks.
- **Implement Referrer-Policy**: Control how much referrer information is shared.
- **Consider X-Frame-Options**: Prevent your site from being framed to avoid clickjacking.

### Implementation

For Next.js applications, you can configure these headers in `next.config.js`:

```javascript
// next.config.js
const securityHeaders = [
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on'
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload'
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block'
  },
  {
    key: 'X-Frame-Options',
    value: 'SAMEORIGIN'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  {
    key: 'Referrer-Policy',
    value: 'origin-when-cross-origin'
  },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};
```

For more advanced CSP configuration, consider using a dedicated middleware or package like Helmet (for Express-based custom servers).

## Conclusion

Security is a continuous process, not a one-time implementation. Regularly review and update your security practices, stay informed about new vulnerabilities and attack vectors, and conduct periodic security assessments of your application.

By following these best practices, you'll significantly reduce the risk of security issues in your Next Auth Kit implementation. Remember that security is all about layers - no single practice provides complete protection, but together they create a robust security posture.

## Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Next.js Security Headers](https://nextjs.org/docs/advanced-features/security-headers)
- [OAuth 2.0 Security Best Practices](https://oauth.net/2/security-best-practices/)