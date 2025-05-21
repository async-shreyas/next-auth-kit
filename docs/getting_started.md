# Getting Started with Next Auth Kit

This guide will walk you through the process of setting up Next Auth Kit in your Next.js application.

## Prerequisites

- Node.js 16.x or later
- Next.js 13.x or later (App Router)
- A PostgreSQL, MySQL, or SQLite database (for storing users and sessions)
- (Optional) OAuth provider credentials (Google, GitHub, etc.)

## Step 1: Installation

Start by installing the Next Auth Kit package:

```bash
# Using npm
npm install next-auth-kit

# Using yarn
yarn add next-auth-kit

# Using pnpm
pnpm add next-auth-kit
```

## Step 2: Set Up the Database

Next Auth Kit requires a specific database schema. The easiest way to set this up is with Prisma.

### Install Prisma

```bash
npm install @prisma/client
npm install prisma --save-dev
```

### Initialize Prisma

```bash
npx prisma init
```

### Set Up the Schema

Create the following schema in your `prisma/schema.prisma` file:

```prisma
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

### Generate the Prisma Client

Run the following commands to create and apply the database migrations:

```bash
npx prisma migrate dev --name init
```

This will create the tables in your database and generate the Prisma client.

### Create a Prisma Client Instance

Create a file at `lib/prisma.ts`:

```typescript
// lib/prisma.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as {
  prisma: PrismaClient | undefined;
};

const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

export default prisma;
```

## Step 3: Configure Authentication

Create a file at `lib/auth.ts` to configure Next Auth Kit:

```typescript
// lib/auth.ts
import { defineConfig, GoogleProvider, GitHubProvider } from 'next-auth-kit';

export const authConfig = defineConfig({
  // A secret string used to sign cookies and tokens
  // Must be at least 32 characters
  secret: process.env.AUTH_SECRET || 'your-development-secret-key-min-32-chars-long',
  
  // Use secure cookies in production
  secureCookies: process.env.NODE_ENV === 'production',
  
  // Your application's base URL
  baseUrl: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
  
  // OAuth providers (optional)
  providers: [
    // Uncomment and configure the providers you want to use
    // GoogleProvider({
    //   clientId: process.env.GOOGLE_CLIENT_ID || '',
    //   clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    // }),
    // GitHubProvider({
    //   clientId: process.env.GITHUB_CLIENT_ID || '',
    //   clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    // }),
  ],
  
  // Public routes that don't require authentication
  publicRoutes: [
    '/',
    '/sign-in',
    '/sign-up',
    '/api/auth/(.*)',
  ],
});
```

## Step 4: Set Up Middleware

Create a `middleware.ts` file at the root of your project:

```typescript
// middleware.ts
import { withAuth } from 'next-auth-kit';
import { authConfig } from './lib/auth';

export default withAuth(authConfig);

export const config = {
  matcher: [
    // Skip Next.js internals and static files
    '/((?!_next|public|favicon.ico|assets).*)',
  ],
};
```

This middleware will protect routes based on the `publicRoutes` configuration.

## Step 5: Create API Routes

Create the necessary API routes for authentication to work:

### Create Registration Handler

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

### Create Login Handler

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

### Create Logout Handler

```typescript
// app/api/auth/logout/route.ts
import { NextRequest } from 'next/server';
import { logoutHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

export async function POST(req: NextRequest) {
  return logoutHandler(req, authConfig);
}
```

### Create Session Handler

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

### Create OAuth Handlers (Optional)

If you're using OAuth providers, create these routes:

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

## Step 6: Add AuthProvider to Your Layout

Wrap your application with the `AuthProvider`:

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

## Step 7: Create Sign In and Sign Up Pages

### Sign In Page

```tsx
// app/sign-in/page.tsx
'use client';

import { LoginForm } from 'next-auth-kit';
import Link from 'next/link';

export default function SignInPage() {
  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sign In</h1>
          <p className="mt-2 text-gray-600">Welcome back!</p>
        </div>
        
        <LoginForm />
        
        <div className="text-center text-sm">
          <p>
            Don't have an account?{' '}
            <Link href="/sign-up" className="text-blue-600 hover:underline">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
```

### Sign Up Page

```tsx
// app/sign-up/page.tsx
'use client';

import { RegisterForm } from 'next-auth-kit';
import Link from 'next/link';

export default function SignUpPage() {
  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Create an Account</h1>
          <p className="mt-2 text-gray-600">Join our platform today</p>
        </div>
        
        <RegisterForm />
        
        <div className="text-center text-sm">
          <p>
            Already have an account?{' '}
            <Link href="/sign-in" className="text-blue-600 hover:underline">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
```

## Step 8: Create a Protected Dashboard Page

```tsx
// app/dashboard/page.tsx
'use client';

import { useUser } from 'next-auth-kit';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function DashboardPage() {
  const { user, isLoading } = useUser();
  const router = useRouter();
  
  // Redirect to sign-in if the user is not authenticated
  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/sign-in');
    }
  }, [user, isLoading, router]);
  
  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p>Loading...</p>
      </div>
    );
  }
  
  if (!user) {
    return null; // Will redirect
  }
  
  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-2">Welcome, {user.name || user.email}!</h2>
        <p>You are now signed in to your account.</p>
      </div>
    </div>
  );
}
```

## Step 9: Add a Navigation Bar with User Button

```tsx
// components/nav-bar.tsx
'use client';

import { useAuth, UserButton } from 'next-auth-kit';
import Link from 'next/link';

export function NavBar() {
  const { user } = useAuth();
  
  return (
    <nav className="bg-white shadow-sm p-4">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <div className="flex items-center">
          <Link href="/" className="text-xl font-bold">
            Your App
          </Link>
          <div className="ml-10 space-x-4">
            <Link href="/" className="hover:text-blue-600">
              Home
            </Link>
            <Link href="/dashboard" className="hover:text-blue-600">
              Dashboard
            </Link>
          </div>
        </div>
        
        <div>
          {user ? (
            <UserButton />
          ) : (
            <div className="space-x-4">
              <Link href="/sign-in" className="hover:text-blue-600">
                Sign In
              </Link>
              <Link href="/sign-up" className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                Sign Up
              </Link>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
```

Add this to your layout:

```tsx
// app/layout.tsx
import { AuthProvider } from 'next-auth-kit';
import { NavBar } from '@/components/nav-bar';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <NavBar />
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

## Step 10: Set Up Environment Variables

Create a `.env` file at the root of your project:

```
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/your_database"

# Auth
AUTH_SECRET="your-secret-key-min-32-characters-long"
NEXT_PUBLIC_APP_URL="http://localhost:3000"

# OAuth (optional)
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
```

Make sure to add `.env` to your `.gitignore` file and set up the environment variables in your production environment.

## Step 11: Start Your Application

Now that everything is set up, you can start your Next.js application:

```bash
npm run dev
```

Visit `http://localhost:3000/sign-up` to create an account, and then you'll be redirected to your dashboard.

## Troubleshooting

### Session Not Persisting

- Make sure your `AUTH_SECRET` is set and is at least 32 characters long.
- Check that your `NEXT_PUBLIC_APP_URL` matches your actual application URL.
- Verify that your database is properly configured and running.

### OAuth Not Working

- Ensure your OAuth provider credentials are correct and that the redirect URIs are properly configured in the provider's dashboard.
- Check that the callback URL is correct (e.g., `http://localhost:3000/api/auth/callback/google`).
- Make sure your application is using HTTPS in production.

### Database Connection Issues

- Verify your `DATABASE_URL` environment variable.
- Ensure your database server is running and accessible.
- Check that the user has the necessary permissions to create and modify tables.

## Next Steps

Now that you have Next Auth Kit set up, you can:

1. **Customize the UI**: Style the authentication forms to match your application's design.
2. **Add Password Reset**: Implement the password reset functionality.
3. **Add Email Verification**: Implement email verification for new accounts.
4. **Implement Role-Based Access Control**: Extend the user model to include roles and permissions.
5. **Add Two-Factor Authentication**: Implement 2FA for enhanced security.

## Additional Resources

- [Next Auth Kit Documentation](https://github.com/your-username/next-auth-kit)
- [Next.js Documentation](https://nextjs.org/docs)
- [Prisma Documentation](https://www.prisma.io/docs)

---

Congratulations! You've successfully set up Next Auth Kit in your Next.js application. If you encounter any issues or have any questions, please refer to the documentation or create an issue on GitHub.