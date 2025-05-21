// src/providers/oauth.ts
import { OAuthProvider } from '../auth.config';

/**
 * Google OAuth provider configuration
 */
export function GoogleProvider(options: {
  clientId: string;
  clientSecret: string;
  scope?: string;
}): OAuthProvider {
  return {
    id: 'google',
    name: 'Google',
    type: 'oauth',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scope: options.scope || 'openid email profile',
  };
}

/**
 * GitHub OAuth provider configuration
 */
export function GitHubProvider(options: {
  clientId: string;
  clientSecret: string;
  scope?: string;
}): OAuthProvider {
  return {
    id: 'github',
    name: 'GitHub',
    type: 'oauth',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scope: options.scope || 'read:user user:email',
  };
}

// Helper function to get provider configuration by ID
export function getProviderById(
  providers: OAuthProvider[],
  providerId: string
): OAuthProvider | null {
  return providers.find(p => p.id === providerId) || null;
}