// src/middleware/auth-middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { AuthConfig } from '../auth.config';
import { jwtVerify } from 'jose';

/**
 * Authentication middleware for Next.js
 */
export function createAuthMiddleware(config: AuthConfig) {
  return async function middleware(request: NextRequest) {
    // Check if the requested route is public
    const isPublicRoute = isPublic(request.nextUrl.pathname, config.publicRoutes);
    
    if (isPublicRoute) {
      return NextResponse.next();
    }
    
    // Get the session token from cookies
    const sessionToken = request.cookies.get(config.cookieName)?.value;
    
    // If no session token, redirect to login
    if (!sessionToken) {
      return redirectToLogin(request, config);
    }
    
    try {
      // Verify JWT token
      const secretKey = new TextEncoder().encode(config.secret);
      await jwtVerify(sessionToken, secretKey, {
        algorithms: ['HS256'],
      });
      
      // Token is valid, continue
      return NextResponse.next();
    } catch (error) {
      // Invalid token, redirect to login
      console.error('Invalid auth token:', error);
      return redirectToLogin(request, config);
    }
  };
}

// Helper to check if a route is public
function isPublic(path: string, publicRoutes: string[]): boolean {
  return publicRoutes.some(pattern => {
    // If pattern ends with (.)*, it's a regex pattern
    if (pattern.endsWith('(.)*')) {
      const regex = new RegExp(`^${pattern.slice(0, -4)}.*$`);
      return regex.test(path);
    }
    // Exact match
    return pattern === path;
  });
}

// Helper to redirect to login page
function redirectToLogin(request: NextRequest, config: AuthConfig): NextResponse {
  const url = request.nextUrl.clone();
  url.pathname = config.loginUrl;
  url.searchParams.set('callbackUrl', request.nextUrl.pathname);
  return NextResponse.redirect(url);
}

/**
 * Export a default middleware configuration for Next.js
 */
export function withAuth(config: AuthConfig) {
  const authMiddleware = createAuthMiddleware(config);
  
  return async function(req: NextRequest) {
    return authMiddleware(req);
  };
}