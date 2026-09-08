"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { quansec } from "@/lib/api";

interface User {
  id: number;
  email: string;
  role: string;
}

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, portal?: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // restore() exchanges the refresh cookie for a new access token, so a
    // session survives a hard reload. loadToken() only reads the in-memory
    // token, which is always empty right after a fresh page load.
    quansec
      .restore()
      .then((ok) => (ok ? quansec.me().then(setUser) : undefined))
      .catch(() => quansec.clearToken())
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string, portal?: string) => {
    await quansec.login(email, password, portal);
    const me = await quansec.me();
    setUser(me);
  };

  const logout = () => {
    quansec.clearToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
