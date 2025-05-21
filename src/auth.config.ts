// src/auth.config.ts
import { z } from 'zod';

export const AuthConfigSchema = z.object({
  // Auth settings
  secret: z.string().min(32).optional(),
  secureCookies: z.boolean().default(false),
  cookieName: z.string().default('auth.session-token'),
  cookieMaxAge: z.number().default(30 * 24 * 60 * 60), // 30 days in seconds
  
  // Route settings
  baseUrl: z.string().default('http://localhost:3000'),
  loginUrl: z.string().default('/sign-in'),
  registerUrl: z.string().default('/sign-up'),
  profileUrl: z.string().default('/profile'),
  defaultLoginRedirect: z.string().default('/dashboard'),
  
  // OAuth providers config
  providers: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      type: z.enum(['oauth', 'email', 'credentials']),
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
      authorizationUrl: z.string().optional(),
      tokenUrl: z.string().optional(),
      userInfoUrl: z.string().optional(),
      scope: z.string().optional().default(''),
    })
  ).default([]),
  
  // Public routes (not protected by auth)
  publicRoutes: z.array(z.string()).default([
    '/',
    '/sign-in',
    '/sign-up',
    '/forgot-password',
    '/reset-password',
    '/api/auth/(.)*',
  ]),
  
  // Pages config
  pages: z.object({
    signIn: z.string().optional(),
    signUp: z.string().optional(),
    error: z.string().optional(),
    verifyRequest: z.string().optional()
  }).default({}),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;

export type OAuthProvider = {
  id: string;
  name: string;
  type: 'oauth';
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scope: string;
};

export type ProviderType = 'oauth' | 'email' | 'credentials';

export interface AuthUser {
  id: string;
  name?: string | null;
  email: string;
  image?: string | null;
  emailVerified?: Date | null;
}

export interface SessionUser extends AuthUser {
  isLoggedIn: boolean;
}

export interface Session {
  user: SessionUser;
  expires: Date;
}

export function defineConfig(config: Partial<AuthConfig>): AuthConfig {
  return AuthConfigSchema.parse({
    ...config,
    secret: config.secret || process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET
  });
}