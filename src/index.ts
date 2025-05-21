// src/index.ts
// Configuration
export { defineConfig } from './auth.config';
export type { 
  AuthConfig, 
  OAuthProvider, 
  ProviderType,
  AuthUser,
  Session,
  SessionUser
} from './auth.config';

// Hooks
export { AuthProvider, useAuth, useUser } from './hooks/use-auth';

// Components
export { 
  LoginForm, 
  RegisterForm, 
  OAuthButton, 
  UserButton 
} from './components/auth-ui';

// Server utilities
export { 
  getSession, 
  getCurrentUser, 
  createSession, 
  destroySession 
} from './server/auth';

// Middleware
export { withAuth } from './middleware/auth-middleware';

// API handlers
export {
  registerHandler,
  loginHandler,
  logoutHandler,
  sessionHandler,
  oauthAuthorizeHandler,
  oauthCallbackHandler
} from './api/auth-handlers';

// OAuth providers
export { 
  GoogleProvider, 
  GitHubProvider 
} from './providers/oauth';

// API route implementation example
export function createAuthRoutes() {
  return `
// app/api/auth/register/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { registerHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function POST(req: NextRequest) {
  return registerHandler(req, authConfig, prisma);
}

// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { loginHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function POST(req: NextRequest) {
  return loginHandler(req, authConfig, prisma);
}

// app/api/auth/logout/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { logoutHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';

export async function POST(req: NextRequest) {
  return logoutHandler(req, authConfig);
}

// app/api/auth/session/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { sessionHandler } from 'next-auth-kit';
import { authConfig } from '@/lib/auth';
import prisma from '@/lib/prisma';

export async function GET(req: NextRequest) {
  return sessionHandler(req, authConfig, prisma);
}

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
  `;
}

// Auth configuration example
export function createAuthConfig() {
  return `
// lib/auth.ts
import { defineConfig, GoogleProvider, GitHubProvider } from 'next-auth-kit';

export const authConfig = defineConfig({
  secret: process.env.AUTH_SECRET,
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
    '/methodology',
  ],
});
  `;
}

// Middleware example
export function createMiddlewareExample() {
  return `
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
  `;
}

// Auth Provider example
export function createAuthProviderExample() {
  return `
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
  `;
}