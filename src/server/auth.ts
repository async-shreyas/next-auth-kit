// src/server/auth.ts
import { cookies } from 'next/headers';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';
import { AuthConfig, Session, SessionUser } from '../auth.config';

export async function getSession(
  config: AuthConfig
): Promise<Session | null> {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get(config.cookieName)?.value;

    if (!sessionToken) {
      return null;
    }

    // Verify the JWT token
    const secretKey = new TextEncoder().encode(config.secret);
    const { payload } = await jwtVerify(sessionToken, secretKey, {
      algorithms: ['HS256'],
    });

    if (!payload || typeof payload.sub !== 'string') {
      return null;
    }

    // Find the session in the database
    const prisma = getPrismaClient();
    const session = await prisma.session.findUnique({
      where: {
        sessionToken,
      },
      include: {
        user: true,
      },
    });

    if (!session || new Date(session.expires) < new Date()) {
      // Session expired, clean it up
      if (session) {
        await prisma.session.delete({
          where: { id: session.id },
        });
      }
      return null;
    }

    // Return the session with user data
    return {
      user: {
        id: session.user.id,
        name: session.user.name,
        email: session.user.email,
        image: session.user.image,
        emailVerified: session.user.emailVerified,
        isLoggedIn: true,
      },
      expires: session.expires,
    };
  } catch (error) {
    console.error('Error getting session:', error);
    return null;
  }
}

export async function getCurrentUser(
  config: AuthConfig
): Promise<SessionUser | null> {
  const session = await getSession(config);
  return session?.user || null;
}

export async function createSession(
  config: AuthConfig,
  userId: string,
  maxAge: number = config.cookieMaxAge
): Promise<string> {
  const prisma = getPrismaClient();
  
  // Create expiration date for the session
  const expires = new Date(Date.now() + maxAge * 1000);
  
  // Generate a unique session token
  const sessionToken = nanoid(32);
  
  // Create a session in the database
  await prisma.session.create({
    data: {
      sessionToken,
      userId,
      expires,
    },
  });
  
  // Create a JWT token for the cookie
  const secretKey = new TextEncoder().encode(config.secret);
  const token = await new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(sessionToken)
    .setIssuedAt()
    .setExpirationTime(expires.toISOString())
    .sign(secretKey);
  
  // Set the cookie
  (await cookies()).set(config.cookieName, token, {
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: 'lax',
    expires,
    path: '/',
  });
  
  return sessionToken;
}

export async function destroySession(config: AuthConfig): Promise<void> {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get(config.cookieName)?.value;
    
    if (sessionToken) {
      const prisma = getPrismaClient();
      
      // Delete the session from the database
      await prisma.session.deleteMany({
        where: {
          sessionToken,
        },
      });
    }
    
    // Clear the cookie
    cookieStore.delete(config.cookieName);
  } catch (error) {
    console.error('Error destroying session:', error);
  }
}

// Helper function to get the Prisma client
function getPrismaClient() {
  // This assumes you have a global PrismaClient instance
  // You might need to adjust this based on your project setup
  return require('../../../lib/prisma').default;
}