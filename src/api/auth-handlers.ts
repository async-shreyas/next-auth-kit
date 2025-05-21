// src/api/auth-handlers.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import { 
  AuthConfig, 
  OAuthProvider 
} from '../auth.config';
import { 
  createSession, 
  destroySession 
} from '../server/auth';

// Schema for registration
const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
});

// Schema for login
const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

// Register handler
export async function registerHandler(
  req: NextRequest,
  config: AuthConfig,
  prisma: any
) {
  try {
    const body = await req.json();
    const validation = registerSchema.safeParse(body);
    
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error.errors },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: validation.data.email }
    });

    if (existingUser) {
      return NextResponse.json(
        { error: 'User with this email already exists' },
        { status: 409 }
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(validation.data.password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        name: validation.data.name,
        email: validation.data.email,
        password: hashedPassword
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true
      }
    });

    // Create session
    await createSession(config, user.id);

    return NextResponse.json(user, { status: 201 });
  } catch (error) {
    console.error('Error registering user:', error);
    return NextResponse.json(
      { error: 'Failed to register user' },
      { status: 500 }
    );
  }
}

// Login handler
export async function loginHandler(
  req: NextRequest,
  config: AuthConfig,
  prisma: any
) {
  try {
    const body = await req.json();
    const validation = loginSchema.safeParse(body);
    
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error.errors },
        { status: 400 }
      );
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: validation.data.email }
    });

    if (!user || !user.password) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Verify password
    const isValid = await bcrypt.compare(validation.data.password, user.password);
    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Create session
    await createSession(config, user.id);

    return NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      image: user.image
    });
  } catch (error) {
    console.error('Error logging in:', error);
    return NextResponse.json(
      { error: 'Failed to log in' },
      { status: 500 }
    );
  }
}

// Logout handler
export async function logoutHandler(
  req: NextRequest,
  config: AuthConfig
) {
  try {
    await destroySession(config);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error logging out:', error);
    return NextResponse.json(
      { error: 'Failed to log out' },
      { status: 500 }
    );
  }
}

// Session handler
export async function sessionHandler(
  req: NextRequest,
  config: AuthConfig,
  prisma: any
) {
  try {
    const cookieStore = req.cookies;
    const sessionToken = cookieStore.get(config.cookieName)?.value;

    if (!sessionToken) {
      return NextResponse.json({ user: null });
    }

    // Find session
    const session = await prisma.session.findUnique({
      where: { sessionToken },
      include: { user: true }
    });

    if (!session || new Date(session.expires) < new Date()) {
      return NextResponse.json({ user: null });
    }

    return NextResponse.json({
      user: {
        id: session.user.id,
        name: session.user.name,
        email: session.user.email,
        image: session.user.image,
        isLoggedIn: true
      }
    });
  } catch (error) {
    console.error('Error getting session:', error);
    return NextResponse.json(
      { error: 'Failed to get session' },
      { status: 500 }
    );
  }
}

// OAuth authorization handler
export async function oauthAuthorizeHandler(
  req: NextRequest,
  config: AuthConfig,
  provider: OAuthProvider
) {
  try {
    // Generate a state parameter for security
    const state = nanoid(32);
    
    // Construct the authorization URL with all parameters
    const authorizationUrl = new URL(provider.authorizationUrl);
    
    authorizationUrl.searchParams.append('client_id', provider.clientId);
    authorizationUrl.searchParams.append('redirect_uri', `${config.baseUrl}/api/auth/callback/${provider.id}`);
    authorizationUrl.searchParams.append('response_type', 'code');
    authorizationUrl.searchParams.append('state', state);
    authorizationUrl.searchParams.append('scope', provider.scope);
    
    // Store the state in a cookie for verification in the callback
    const response = NextResponse.redirect(authorizationUrl.toString());
    response.cookies.set('oauth_state', state, {
      httpOnly: true,
      secure: config.secureCookies,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 10, // 10 minutes
    });
    
    return response;
  } catch (error) {
    console.error(`Error authorizing with ${provider.name}:`, error);
    return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=OAuthError`);
  }
}

// OAuth callback handler
export async function oauthCallbackHandler(
  req: NextRequest,
  config: AuthConfig,
  provider: OAuthProvider,
  prisma: any
) {
  try {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');
    
    // Handle OAuth errors
    if (error) {
      console.error(`OAuth error: ${error}`);
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=OAuthError`);
    }
    
    // Validate required parameters
    if (!code || !state) {
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=MissingParameters`);
    }
    
    // Verify state parameter to prevent CSRF
    const cookieState = req.cookies.get('oauth_state')?.value;
    if (!cookieState || cookieState !== state) {
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=InvalidState`);
    }
    
    // Exchange code for token
    const tokenResponse = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${config.baseUrl}/api/auth/callback/${provider.id}`,
      }),
    });
    
    if (!tokenResponse.ok) {
      console.error('Error exchanging code for token:', await tokenResponse.text());
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=TokenExchange`);
    }
    
    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;
    
    // Get user info
    const userInfoResponse = await fetch(provider.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    
    if (!userInfoResponse.ok) {
      console.error('Error getting user info:', await userInfoResponse.text());
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=UserInfo`);
    }
    
    const userData = await userInfoResponse.json();
    
    // Extract user details (adjust based on provider's response format)
    const email = userData.email;
    const name = userData.name || userData.display_name;
    const image = userData.picture || userData.avatar_url;
    
    if (!email) {
      return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=NoEmail`);
    }
    
    // Find or create user
    let user = await prisma.user.findUnique({
      where: { email },
    });
    
    if (!user) {
      // Create new user
      user = await prisma.user.create({
        data: {
          email,
          name,
          image,
          emailVerified: new Date(),
        },
      });
    } else {
      // Update existing user
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          name: name || user.name,
          image: image || user.image,
          emailVerified: user.emailVerified || new Date(),
        },
      });
    }
    
    // Create or update account
    await prisma.account.upsert({
      where: {
        provider_providerAccountId: {
          provider: provider.id,
          providerAccountId: userData.id.toString(),
        },
      },
      update: {
        access_token: accessToken,
        expires_at: tokenData.expires_in 
          ? Math.floor(Date.now() / 1000) + tokenData.expires_in
          : null,
        refresh_token: tokenData.refresh_token,
        id_token: tokenData.id_token,
        scope: provider.scope,
        token_type: tokenData.token_type,
      },
      create: {
        userId: user.id,
        provider: provider.id,
        providerAccountId: userData.id.toString(),
        access_token: accessToken,
        expires_at: tokenData.expires_in 
          ? Math.floor(Date.now() / 1000) + tokenData.expires_in
          : null,
        refresh_token: tokenData.refresh_token,
        id_token: tokenData.id_token,
        scope: provider.scope,
        token_type: tokenData.token_type,
      },
    });
    
    // Create session
    await createSession(config, user.id);
    
    // Redirect to success page
    const response = NextResponse.redirect(`${config.baseUrl}${config.defaultLoginRedirect}`);
    
    // Clean up the state cookie
    response.cookies.delete('oauth_state');
    
    return response;
  } catch (error) {
    console.error(`Error handling callback for ${provider.name}:`, error);
    return NextResponse.redirect(`${config.baseUrl}${config.loginUrl}?error=CallbackError`);
  }
}