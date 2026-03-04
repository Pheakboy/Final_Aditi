"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { User, AuthResponse } from "../types";
import { authApi } from "../services/api";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
  ) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAdmin = user?.roles?.includes("ADMIN") ?? false;

  useEffect(() => {
    const storedToken = localStorage.getItem("accessToken");
    const storedUser = localStorage.getItem("user");
    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
    }
    setIsLoading(false);

    // Sync token state when the interceptor clears localStorage (e.g. after silent refresh)
    const handleStorage = (e: StorageEvent) => {
      if (e.key === "accessToken") {
        setToken(e.newValue);
      }
      if (e.key === "user") {
        setUser(e.newValue ? JSON.parse(e.newValue) : null);
      }
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const login = async (email: string, password: string) => {
    const response = await authApi.login({ email, password });
    const data: AuthResponse = response.data.data;
    localStorage.setItem("accessToken", data.accessToken);
    setToken(data.accessToken);

    // Fetch user profile
    const meResponse = await authApi.me();
    const userData: User = meResponse.data.data;
    localStorage.setItem("user", JSON.stringify(userData));
    setUser(userData);
  };

  const register = async (
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
  ) => {
    await authApi.register({ username, email, password, confirmPassword });
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch {
      // ignore errors on logout
    }
    localStorage.removeItem("accessToken");
    localStorage.removeItem("user");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, token, isLoading, isAdmin, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
