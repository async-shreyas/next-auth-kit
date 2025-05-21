# Next Auth Kit

![Version](https://img.shields.io/npm/v/next-auth-kit)
![License](https://img.shields.io/npm/l/next-auth-kit)
![Downloads](https://img.shields.io/npm/dm/next-auth-kit)

A comprehensive authentication solution for Next.js applications that provides session management, OAuth providers, JWT handling, and UI components out of the box.

## Features

- 🔐 **Complete Authentication Flow**: Login, registration, password reset, and OAuth
- 🔄 **Session Management**: JWT-based sessions with secure HTTP-only cookies
- 🌐 **OAuth Integration**: Ready-to-use Google and GitHub OAuth providers
- 🧩 **UI Components**: Pre-styled authentication forms and buttons
- 🛡️ **Middleware**: Route protection with configurable public routes
- 📦 **TypeScript Support**: Full type definitions for a better development experience
- 🎛️ **Customizable**: Flexible configuration to adapt to your project needs

## Installation

```bash
# npm
npm install next-auth-kit

# yarn
yarn add next-auth-kit

# pnpm
pnpm add next-auth-kit
```

## Quick Start

### 1. Configure Authentication

Create a configuration file at `lib/auth.ts`:

```typescript
// lib/auth.ts
import { defineConfig, GoogleProvider, GitHubProvider } from 'next-auth-kit';

export const authConfig = defineConfig({
  secret: process.env.AUTH_SECRET || 'your-secret-key-min-32-chars-long',
  secureCookies: process.env.NODE_ENV === 'production',
  baseUrl: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
  
  // OAuth providers
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
  
  // Public routes (not protected by auth)
  publicRoutes: [
    '/',
    '/sign-in',
    '/sign-up',
    '/api/auth/(.*)',
  ],
});
```

### 2. Set Up Middleware

Create a middleware file at the root of your project:

```typescript
// middleware.ts
import { withAuth } from 'next-auth-kit';
import { authConfig } from './lib/auth';

export default withAuth(authConfig);

export const config = {
  matcher: [
    // Skip Next.js internals and static files
    '/((?!_next|public|favicon.ico).*)',
  ],
};
```

### 3. Add AuthProvider to Your Layout

Wrap your application with the AuthProvider:

```tsx
// app/layout.tsx
import { AuthProvider } from 'next-auth-kit';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### 4. Create API Routes

Create the necessary API routes for authentication:

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

```typescript
// app/api/auth/logout/route.ts
import { NextRequest } from 'next/server';
import { logoutHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

export async function POST(req: NextRequest) {
  return logoutHandler(req, authConfig);
}
```

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

For OAuth providers, create these routes:

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

### 5. Create Sign In and Sign Up Pages

Create a sign-in page using the provided components:

```tsx
// app/sign-in/page.tsx
'use client';

import { LoginForm } from 'next-auth-kit';

export default function SignInPage() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sign In</h1>
          <p className="mt-2 text-gray-600">Welcome back!</p>
        </div>
        
        <LoginForm />
        
        <div className="text-center text-sm">
          <p>
            Don't have an account?{' '}
            <a href="/sign-up" className="text-blue-600 hover:underline">
              Sign Up
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
```

Create a sign-up page:

```tsx
// app/sign-up/page.tsx
'use client';

import { RegisterForm } from 'next-auth-kit';

export default function SignUpPage() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Create an Account</h1>
          <p className="mt-2 text-gray-600">Join our platform today</p>
        </div>
        
        <RegisterForm />
        
        <div className="text-center text-sm">
          <p>
            Already have an account?{' '}
            <a href="/sign-in" className="text-blue-600 hover:underline">
              Sign In
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
```

### 6. Use Authentication in Your Components

Use the authentication hooks in your components:

```tsx
'use client';

import { useAuth, useUser, UserButton } from 'next-auth-kit';

export function ProfilePage() {
  const { user, isLoading } = useUser();
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  if (!user) {
    return <div>Not signed in</div>;
  }
  
  return (
    <div>
      <h1>Profile</h1>
      <div className="flex justify-between items-center">
        <div>
          <p>Welcome, {user.name || user.email}</p>
          <p>Email: {user.email}</p>
        </div>
        <UserButton />
      </div>
    </div>
  );
}

export function NavBar() {
  const { user, logout } = useAuth();
  
  return (
    <nav className="flex justify-between items-center p-4 bg-white shadow">
      <div className="font-bold text-xl">Your App</div>
      <div>
        {user ? (
          <div className="flex items-center gap-4">
            <span>Hello, {user.name || user.email}</span>
            <UserButton />
          </div>
        ) : (
          <div className="space-x-4">
            <a href="/sign-in" className="text-blue-600 hover:underline">Sign In</a>
            <a href="/sign-up" className="px-4 py-2 bg-blue-600 text-white rounded">Sign Up</a>
          </div>
        )}
      </div>
    </nav>
  );
}
```

## Database Schema

Next Auth Kit requires a specific database schema. Here's an example using Prisma:

```prisma
// schema.prisma
datasource db {
  provider = "postgresql" // or "mysql", "sqlite", etc.
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id            String    @id @default(cuid())
  name          String?
  email         String    @unique
  emailVerified DateTime?
  image         String?
  password      String?
  accounts      Account[]
  sessions      Session[]
}

model Account {
  id                String  @id @default(cuid())
  userId            String
  type              String
  provider          String
  providerAccountId String
  refresh_token     String? @db.Text
  access_token      String? @db.Text
  expires_at        Int?
  token_type        String?
  scope             String?
  id_token          String? @db.Text
  session_state     String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([provider, providerAccountId])
}

model Session {
  id           String   @id @default(cuid())
  sessionToken String   @unique
  userId       String
  expires      DateTime
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
}

model VerificationToken {
  identifier String
  token      String   @unique
  expires    DateTime

  @@unique([identifier, token])
}
```

## Advanced Configuration

### Custom Hooks

You can create custom hooks that build on top of the provided hooks:

```typescript
// hooks/use-auth-redirect.ts
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from 'next-auth-kit';

export function useAuthRedirect(redirectTo: string = '/sign-in') {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  
  useEffect(() => {
    if (!isLoading && !user) {
      router.push(redirectTo);
    }
  }, [user, isLoading, router, redirectTo]);
  
  return { user, isLoading };
}
```

### Custom Styling

The provided components accept a `className` prop that can be used to customize styling:

```tsx
<LoginForm className="p-6 rounded-xl bg-gray-50" />
```

You can also create your own styled components:

```tsx
import { useAuth } from 'next-auth-kit';

function CustomLoginForm() {
  const { login, isLoading, error } = useAuth();
  // Your custom implementation...
}
```

## API Reference

### Configuration

#### `defineConfig(options)`

Creates a configuration object for Next Auth Kit.

Options:
- `secret`: String - The secret used to sign tokens (required, min 32 chars)
- `secureCookies`: Boolean - Whether to use secure cookies (default: false)
- `cookieName`: String - The name of the session cookie (default: 'auth.session-token')
- `cookieMaxAge`: Number - Cookie max age in seconds (default: 30 days)
- `baseUrl`: String - Base URL of your application (default: 'http://localhost:3000')
- `loginUrl`: String - Login page URL (default: '/sign-in')
- `registerUrl`: String - Registration page URL (default: '/sign-up')
- `profileUrl`: String - Profile page URL (default: '/profile')
- `defaultLoginRedirect`: String - Redirect URL after login (default: '/dashboard')
- `providers`: Array - OAuth providers configuration
- `publicRoutes`: Array - Routes that don't require authentication

### Hooks

#### `useAuth()`

The main authentication hook that provides all auth-related functionality.

Returns:
- `session`: Session | null - The current session object
- `user`: SessionUser | null - The current user object
- `isLoading`: boolean - Whether the authentication state is loading
- `error`: string | null - Any error that occurred during authentication
- `login`: (email: string, password: string) => Promise<void> - Login function
- `register`: (name: string, email: string, password: string) => Promise<void> - Registration function
- `logout`: () => Promise<void> - Logout function
- `oauthSignIn`: (provider: string) => Promise<void> - OAuth sign-in function

#### `useUser()`

A simplified hook that only provides user information.

Returns:
- `user`: SessionUser | null - The current user object
- `isLoading`: boolean - Whether the user data is loading

### Components

#### `<AuthProvider>`

Provider component that wraps your application and provides authentication context.

Props:
- `children`: ReactNode - Child components
- `loginRedirect`: string - Redirect URL after login (default: '/dashboard')

#### `<LoginForm>`

A pre-styled login form component.

Props:
- `className`: string - Additional CSS classes
- `onSuccess`: () => void - Callback function after successful login

#### `<RegisterForm>`

A pre-styled registration form component.

Props:
- `className`: string - Additional CSS classes
- `onSuccess`: () => void - Callback function after successful registration

#### `<OAuthButton>`

A button component for OAuth authentication.

Props:
- `provider`: string - The OAuth provider ID (e.g., 'google', 'github')

#### `<UserButton>`

A user profile button component that displays user information and a dropdown menu.

Props:
- `afterSignOutUrl`: string - URL to redirect to after sign out (default: '/sign-in')

### Server Utilities

#### `getSession(config)`

Gets the current session from the request.

Returns: Promise<Session | null>

#### `getCurrentUser(config)`

Gets the current user from the session.

Returns: Promise<SessionUser | null>

## Environment Variables

```
# Required
AUTH_SECRET=your-secret-key-min-32-chars-long
DATABASE_URL=your-database-connection-string

# OAuth Providers (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Application URLs
NEXT_PUBLIC_APP_URL=https://your-app-url.com
```

## Security Considerations

1. **JWT Secret**: Use a strong, unique secret with at least 32 characters
2. **HTTPS**: Always use HTTPS in production
3. **Cookie Security**: Enable secure cookies in production
4. **CSRF Protection**: The package provides CSRF protection for OAuth flows
5. **Password Requirements**: Enforce strong password requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

- [Next.js](https://nextjs.org/)
- [Jose](https://github.com/panva/jose) - JWT implementation
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) - Password hashing
- [Zod](https://github.com/colinhacks/zod) - Schema validation

---

Made with ❤️ by [Your Name]