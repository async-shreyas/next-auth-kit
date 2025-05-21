// src/hooks/use-auth.tsx
'use client';

import { 
  createContext, 
  useContext, 
  useEffect, 
  useState, 
  ReactNode 
} from 'react';
import { Session, SessionUser } from '../auth.config';
import { useRouter } from 'next/navigation';

interface AuthContextType {
  session: Session | null;
  user: SessionUser | null;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  oauthSignIn: (provider: string) => Promise<void>;
}

const defaultContext: AuthContextType = {
  session: null,
  user: null,
  isLoading: true,
  error: null,
  login: async () => {},
  register: async () => {},
  logout: async () => {},
  oauthSignIn: async () => {},
};

const AuthContext = createContext<AuthContextType>(defaultContext);

export function AuthProvider({ 
  children,
  loginRedirect = '/dashboard',
}: { 
  children: ReactNode;
  loginRedirect?: string;
}) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<SessionUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  // Fetch session on mount
  useEffect(() => {
    async function loadSession() {
      try {
        setIsLoading(true);
        const response = await fetch('/api/auth/session');
        const data = await response.json();
        
        if (data.user) {
          setSession({ user: data.user, expires: new Date(data.expires) });
          setUser(data.user);
        } else {
          setSession(null);
          setUser(null);
        }
      } catch (err) {
        console.error('Failed to load session:', err);
        setError('Failed to load user session');
      } finally {
        setIsLoading(false);
      }
    }

    loadSession();
  }, []);

  // Login function
  const login = async (email: string, password: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      
      // Success! Refresh the session
      const sessionResponse = await fetch('/api/auth/session');
      const sessionData = await sessionResponse.json();
      
      if (sessionData.user) {
        setSession({ 
          user: sessionData.user, 
          expires: new Date(sessionData.expires) 
        });
        setUser(sessionData.user);
        router.push(loginRedirect);
      }
    } catch (err) {
      console.error('Login error:', err);
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  // Register function
  const register = async (name: string, email: string, password: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, email, password }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      
      // Success! Refresh the session
      const sessionResponse = await fetch('/api/auth/session');
      const sessionData = await sessionResponse.json();
      
      if (sessionData.user) {
        setSession({ 
          user: sessionData.user, 
          expires: new Date(sessionData.expires) 
        });
        setUser(sessionData.user);
        router.push(loginRedirect);
      }
    } catch (err) {
      console.error('Registration error:', err);
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  // Logout function
  const logout = async () => {
    try {
      setIsLoading(true);
      await fetch('/api/auth/logout', { method: 'POST' });
      setSession(null);
      setUser(null);
      router.push('/sign-in');
    } catch (err) {
      console.error('Logout error:', err);
      setError('Failed to log out');
    } finally {
      setIsLoading(false);
    }
  };

  // OAuth sign in
  const oauthSignIn = async (provider: string) => {
    try {
      // We redirect to the OAuth flow
      window.location.href = `/api/auth/${provider}`;
    } catch (err) {
      console.error(`OAuth sign in error with ${provider}:`, err);
      setError(`Failed to sign in with ${provider}`);
    }
  };

  const contextValue: AuthContextType = {
    session,
    user,
    isLoading,
    error,
    login,
    register,
    logout,
    oauthSignIn,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
}

export function useUser() {
  const { user, isLoading } = useAuth();
  return { user, isLoading };
}