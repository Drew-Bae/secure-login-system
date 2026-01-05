import { BrowserRouter, Routes, Route, Link, useNavigate } from "react-router-dom";
import Home from "./pages/Home";
import Register from "./pages/Register";
import Login from "./pages/Login";
import AdminLoginAttempts from "./pages/AdminLoginAttempts";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import MfaVerify from "./pages/MfaVerify";
import MfaSetup from "./pages/MfaSetup";
import Security from "./pages/Security";
import Devices from "./pages/Devices";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminRoute from "./components/AdminRoute";
import StepUpVerify from "./pages/StepUpVerify";
import AdminUsers from "./pages/AdminUsers";
import AdminUserDetail from "./pages/AdminUserDetail";
import AdminAuditLog from "./pages/AdminAuditLog";
import AdminBlockedIps from "./pages/AdminBlockedIps";
import VerifyEmail from "./pages/VerifyEmail";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppHeader />

        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/mfa-verify" element={<MfaVerify />} />
          <Route path="/step-up/verify" element={<StepUpVerify />} />
          <Route path="/verify-email" element={<VerifyEmail />} />

          {/* Authenticated routes */}
          <Route
            path="/mfa/setup"
            element={
              <ProtectedRoute>
                <MfaSetup />
              </ProtectedRoute>
            }
          />
          <Route
            path="/security"
            element={
              <ProtectedRoute>
                <Security />
              </ProtectedRoute>
            }
          />
          <Route
            path="/devices"
            element={
              <ProtectedRoute>
                <Devices />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/login-attempts"
            element={
              <AdminRoute>
                <AdminLoginAttempts />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/users"
            element={
              <AdminRoute>
                <AdminUsers />
              </AdminRoute>
            }
          />

          <Route
            path="/admin/users/:userId"
            element={
              <AdminRoute>
                <AdminUserDetail />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/audit"
            element={
              <AdminRoute>
                <AdminAuditLog />
              </AdminRoute>
            }
          />

          <Route
            path="/admin/blocked-ips"
            element={
              <AdminRoute>
                <AdminBlockedIps />
              </AdminRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

function AppHeader() {
  const navigate = useNavigate();
  const { user, initializing, logout } = useAuth();

  async function handleLogout() {
    try {
      await logout();
    } finally {
      navigate("/login");
    }
  }

  return (
    <header
      style={{
        padding: "12px 24px",
        borderBottom: "1px solid #444",
        marginBottom: 24,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        fontFamily: "system-ui",
        gap: 16,
      }}
    >
      <span>Secure Login System</span>

      <nav style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <Link to="/">Home</Link>

        {!user && !initializing && (
          <>
            <Link to="/register">Register</Link>
            <Link to="/login">Login</Link>
            <Link to="/forgot-password">Forgot Password</Link>
          </>
        )}

        {user && (
          <>
            <Link to="/security">Security</Link>
            <Link to="/devices">Devices</Link>
            <Link to="/mfa/setup">MFA Setup</Link>
            {user.role === "admin" && (
              <>
                <Link to="/admin/login-attempts">Admin Attempts</Link>
                <Link to="/admin/users">Admin Users</Link>
                <Link to="/admin/audit">Admin Audit</Link>
                <Link to="/admin/blocked-ips">Admin Blocked IPs</Link>
              </>
            )}
            <span style={{ opacity: 0.85, marginLeft: 8 }}>
              Signed in as <strong>{user.email}</strong>
            </span>
            <button
              type="button"
              onClick={handleLogout}
              style={{ marginLeft: 8, padding: "6px 12px" }}
            >
              Logout
            </button>
          </>
        )}

        {initializing && (
          <span style={{ opacity: 0.75, marginLeft: 8 }}>Checking session...</span>
        )}
      </nav>
    </header>
  );
}
