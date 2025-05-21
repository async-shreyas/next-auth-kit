# Next Auth Kit API Reference

This document provides a detailed reference for all the APIs, components, hooks, and utilities available in the Next Auth Kit package.

## Table of Contents

1. [Configuration](#configuration)
2. [Hooks](#hooks)
3. [Components](#components)
4. [Server Utilities](#server-utilities)
5. [API Route Handlers](#api-route-handlers)
6. [OAuth Providers](#oauth-providers)
7. [Middleware](#middleware)
8. [Types](#types)

## Configuration

### `defineConfig(options)`

Creates a configuration object for Next Auth Kit with type validation.

**Parameters:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `secret` | `string` | Secret key used to sign JWT tokens | Required (or from env) |
| `secureCookies` | `boolean` | Whether to use secure cookies | `false` |
| `cookieName` | `string` | Name of the session cookie | `'auth.session-token'` |
| `cookieMaxAge` | `number` | Cookie max age in seconds | `30 * 24 * 60 * 60` (30 days) |
| `baseUrl` | `string` | Base URL of your application | `'http://localhost:3000'` |
| `loginUrl` | `string` | Login page URL | `'/sign-in'` |
| `registerUrl` | `string` | Registration page URL | `'/sign-up'` |
| `profileUrl` | `string` | Profile page URL | `'/profile'` |
| `defaultLoginRedirect` | `string` | Redirect URL after login | `'/dashboard'` |
| `providers` | `OAuthProvider[]` | OAuth providers configuration | `[]` |
| `publicRoutes` | `string[]` | Routes that don't require authentication | `['/', '/sign-in', '/sign-up', '/api/auth/(.)*']` |
| `pages` | `object` | Custom pages configuration | `{}` |

**Example:**

```typescript
import { defineConfig, GoogleProvider, GitHubProvider } from 'next-auth-kit';

export const authConfig = defineConfig({
  secret: process.env.AUTH_SECRET,
  secureCookies: process.env.NODE_ENV === 'production',
  baseUrl: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    }),
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID || '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    }),
  ],
  publicRoutes: [
    '/',
    '/sign-in',
    '/sign-up',
    '/api/auth/(.*)',
  ],
});
```

## Hooks

### `useAuth()`

The main authentication hook that provides all auth-related functionality.

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `session` | `Session \| null` | The current session object |
| `user` | `SessionUser \| null` | The current user object |
| `isLoading` | `boolean` | Whether authentication state is loading |
| `error` | `string \| null` | Any error that occurred during authentication |
| `login` | `(email: string, password: string) => Promise<void>` | Function to log in |
| `register` | `(name: string, email: string, password: string) => Promise<void>` | Function to register |
| `logout` | `() => Promise<void>` | Function to log out |
| `oauthSignIn` | `(provider: string) => Promise<void>` | Function to sign in with OAuth |

**Example:**

```tsx
import { useAuth } from 'next-auth-kit';

function LoginPage() {
  const { login, isLoading, error } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    await login('user@example.com', 'password123');
  };
  
  return (
    <form onSubmit={handleSubmit}>
      {/* Form fields */}
      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Log in'}
      </button>
    </form>
  );
}
```

### `useUser()`

A simplified hook that only provides user information.

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `user` | `SessionUser \| null` | The current user object |
| `isLoading` | `boolean` | Whether user data is loading |

**Example:**

```tsx
import { useUser } from 'next-auth-kit';

function ProfilePage() {
  const { user, isLoading } = useUser();
  
  if (isLoading) return <div>Loading...</div>;
  if (!user) return <div>Not signed in</div>;
  
  return (
    <div>
      <h1>Welcome, {user.name || user.email}</h1>
      <p>Email: {user.email}</p>
    </div>
  );
}
```

## Components

### `<AuthProvider>`

Provider component that wraps your application and provides authentication context.

**Props:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `children` | `ReactNode` | Child components | Required |
| `loginRedirect` | `string` | Redirect URL after login | `'/dashboard'` |

**Example:**

```tsx
import { AuthProvider } from 'next-auth-kit';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider loginRedirect="/dashboard">
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### `<LoginForm>`

A pre-styled login form component.

**Props:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `className` | `string` | Additional CSS classes | `''` |
| `onSuccess` | `() => void` | Callback after successful login | Optional |

**Example:**

```tsx
import { LoginForm } from 'next-auth-kit';

export default function SignInPage() {
  return (
    <div className="auth-container">
      <h1>Sign In</h1>
      <LoginForm 
        className="my-custom-form" 
        onSuccess={() => console.log('Logged in!')}
      />
    </div>
  );
}
```

### `<RegisterForm>`

A pre-styled registration form component.

**Props:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `className` | `string` | Additional CSS classes | `''` |
| `onSuccess` | `() => void` | Callback after successful registration | Optional |

**Example:**

```tsx
import { RegisterForm } from 'next-auth-kit';

export default function SignUpPage() {
  return (
    <div className="auth-container">
      <h1>Create Account</h1>
      <RegisterForm 
        className="my-custom-form" 
        onSuccess={() => console.log('Registered!')}
      />
    </div>
  );
}
```

### `<OAuthButton>`

A button component for OAuth authentication.

**Props:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `provider` | `string` | The OAuth provider ID | Required |

**Example:**

```tsx
import { OAuthButton } from 'next-auth-kit';

export default function AuthButtons() {
  return (
    <div className="oauth-container">
      <OAuthButton provider="google" />
      <OAuthButton provider="github" />
    </div>
  );
}
```

### `<UserButton>`

A user profile button component that displays user information and a dropdown menu.

**Props:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `afterSignOutUrl` | `string` | URL to redirect to after sign out | `'/sign-in'` |

**Example:**

```tsx
import { UserButton } from 'next-auth-kit';

export default function NavBar() {
  return (
    <nav>
      <div className="logo">My App</div>
      <UserButton afterSignOutUrl="/" />
    </nav>
  );
}
```

## Server Utilities

### `getSession(config)`

Gets the current session from the request.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `config` | `AuthConfig` | Auth configuration object |

**Returns:** `Promise<Session | null>`

**Example:**

```typescript
import { getSession } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

async function getServerSideProps(context) {
  const session = await getSession(authConfig);
  
  if (!session) {
    return {
      redirect: {
        destination: '/sign-in',
        permanent: false,
      },
    };
  }
  
  return {
    props: { user: session.user },
  };
}
```

### `getCurrentUser(config)`

Gets the current user from the session.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `config` | `AuthConfig` | Auth configuration object |

**Returns:** `Promise<SessionUser | null>`

**Example:**

```typescript
import { getCurrentUser } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

async function getUserData() {
  const user = await getCurrentUser(authConfig);
  
  if (!user) {
    return null;
  }
  
  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
}
```

### `createSession(config, userId, maxAge?)`

Creates a new session for the user.

**Parameters:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `config` | `AuthConfig` | Auth configuration object | Required |
| `userId` | `string` | User ID | Required |
| `maxAge` | `number` | Session max age in seconds | `config.cookieMaxAge` |

**Returns:** `Promise<string>` (session token)

**Example:**

```typescript
import { createSession } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

async function logUserIn(userId) {
  const sessionToken = await createSession(authConfig, userId);
  return sessionToken;
}
```

### `destroySession(config)`

Destroys the current session.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `config` | `AuthConfig` | Auth configuration object |

**Returns:** `Promise<void>`

**Example:**

```typescript
import { destroySession } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

async function logUserOut() {
  await destroySession(authConfig);
}
```

## API Route Handlers

### `registerHandler(req, config, prisma)`

Handles user registration.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |
| `prisma` | `PrismaClient` | Prisma client instance |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/register/route.ts
import { NextRequest } from 'next/server';
import { registerHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function POST(req: NextRequest) {
  return registerHandler(req, authConfig, prisma);
}
```

### `loginHandler(req, config, prisma)`

Handles user login.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |
| `prisma` | `PrismaClient` | Prisma client instance |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/login/route.ts
import { NextRequest } from 'next/server';
import { loginHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function POST(req: NextRequest) {
  return loginHandler(req, authConfig, prisma);
}
```

### `logoutHandler(req, config)`

Handles user logout.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/logout/route.ts
import { NextRequest } from 'next/server';
import { logoutHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

export async function POST(req: NextRequest) {
  return logoutHandler(req, authConfig);
}
```

### `sessionHandler(req, config, prisma)`

Handles session retrieval.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |
| `prisma` | `PrismaClient` | Prisma client instance |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/session/route.ts
import { NextRequest } from 'next/server';
import { sessionHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function GET(req: NextRequest) {
  return sessionHandler(req, authConfig, prisma);
}
```

### `oauthAuthorizeHandler(req, config, provider)`

Handles OAuth authorization.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |
| `provider` | `OAuthProvider` | OAuth provider configuration |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/[provider]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { oauthAuthorizeHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import { getProviderById } from 'next-auth-kit/providers/oauth';

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

### `oauthCallbackHandler(req, config, provider, prisma)`

Handles OAuth callback.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `NextRequest` | Next.js request object |
| `config` | `AuthConfig` | Auth configuration object |
| `provider` | `OAuthProvider` | OAuth provider configuration |
| `prisma` | `PrismaClient` | Prisma client instance |

**Returns:** `Promise<NextResponse>`

**Example:**

```typescript
// app/api/auth/callback/[provider]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { oauthCallbackHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import { getProviderById } from 'next-auth-kit/providers/oauth';
import prisma from '@/lib/prisma';

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
  
  return oauthCallbackHandler(req, authConfig, provider, prisma);
}
```

## OAuth Providers

### `GoogleProvider(options)`

Creates a Google OAuth provider configuration.

**Parameters:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `options.clientId` | `string` | Google OAuth client ID | Required |
| `options.clientSecret` | `string` | Google OAuth client secret | Required |
| `options.scope` | `string` | OAuth scope | `'openid email profile'` |

**Returns:** `OAuthProvider`

**Example:**

```typescript
import { GoogleProvider } from 'next-auth-kit';

const googleProvider = GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  scope: 'openid email profile',
});
```

### `GitHubProvider(options)`

Creates a GitHub OAuth provider configuration.

**Parameters:**

| Name | Type | Description | Default |
|------|------|-------------|---------|
| `options.clientId` | `string` | GitHub OAuth client ID | Required |
| `options.clientSecret` | `string` | GitHub OAuth client secret | Required |
| `options.scope` | `string` | OAuth scope | `'read:user user:email'` |

**Returns:** `OAuthProvider`

**Example:**

```typescript
import { GitHubProvider } from 'next-auth-kit';

const githubProvider = GitHubProvider({
  clientId: process.env.GITHUB_CLIENT_ID || '',
  clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  scope: 'read:user user:email',
});
```

### `getProviderById(providers, providerId)`

Gets an OAuth provider configuration by ID.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `providers` | `OAuthProvider[]` | Array of OAuth providers |
| `providerId` | `string` | Provider ID to find |

**Returns:** `OAuthProvider | null`

**Example:**

```typescript
import { getProviderById } from 'next-auth-kit/providers/oauth';

const provider = getProviderById(authConfig.providers, 'google');
```

## Middleware

### `withAuth(config)`

Creates a middleware function that protects routes based on the configuration.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `config` | `AuthConfig` | Auth configuration object |

**Returns:** `(req: NextRequest) => Promise<NextResponse>`

**Example:**

```typescript
// middleware.ts
import { withAuth } from 'next-auth-kit';
import { authConfig } from './lib/auth';

export default withAuth(authConfig);

export const config = {
  matcher: [
    '/((?!_next|public|favicon.ico).*)',
  ],
};
```

## Types

### `AuthConfig`

Configuration object type.

```typescript
interface AuthConfig {
  secret: string;
  secureCookies: boolean;
  cookieName: string;
  cookieMaxAge: number;
  baseUrl: string;
  loginUrl: string;
  registerUrl: string;
  profileUrl: string;
  defaultLoginRedirect: string;
  providers: OAuthProvider[];
  publicRoutes: string[];
  pages: {
    signIn?: string;
    signUp?: string;
    error?: string;
    verifyRequest?: string;
  };
}
```

### `OAuthProvider`

OAuth provider configuration type.

```typescript
interface OAuthProvider {
  id: string;
  name: string;
  type: 'oauth';
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scope: string;
}
```

### `Session`

Session object type.

```typescript
interface Session {
  user: SessionUser;
  expires: Date;
}
```

### `SessionUser`

User object in session type.

```typescript
interface SessionUser extends AuthUser {
  isLoggedIn: boolean;
}
```

### `AuthUser`

Base user object type.

```typescript
interface AuthUser {
  id: string;
  name?: string | null;
  email: string;
  image?: string | null;
  emailVerified?: Date | null;
}
```

This completes the documentation for the Next Auth Kit API. If you have any questions or need further clarification, please refer to the examples or create an issue in the GitHub repository.