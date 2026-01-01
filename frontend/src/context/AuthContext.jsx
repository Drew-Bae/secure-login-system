import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { fetchMe, loginUser, logoutUser } from "../api/auth";

const AuthContext = createContext(null);

/**
 * AuthProvider
 * - Persists session using HttpOnly cookie via GET /api/auth/me
 * - Exposes login/logout helpers and the current user object
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [initializing, setInitializing] = useState(true);

  const refreshMe = useCallback(async () => {
    try {
      const res = await fetchMe();
      setUser(res.data?.user || null);
      return res.data?.user || null;
    } catch (err) {
      const code = err.response?.status;
      if (code === 401 || code === 403) {
        setUser(null);
        return null;
      }
      throw err;
    }
  }, []);

  const login = useCallback(
    async ({ email, password }) => {
      const res = await loginUser({ email, password });

      // If MFA step-up required, do NOT call /me yet
      if (res.data?.mfaRequired) return res;

      // Normal login: cookie is now set — load user data
      await refreshMe();
      return res;
    },
    [refreshMe]
  );

  const logout = useCallback(async () => {
    await logoutUser();
    setUser(null);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        await refreshMe();
      } finally {
        setInitializing(false);
      }
    })();
  }, [refreshMe]);

  const value = useMemo(
    () => ({ user, initializing, refreshMe, login, logout }),
    [user, initializing, refreshMe, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
