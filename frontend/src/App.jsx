import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import Home from "./pages/Home";
import Register from "./pages/Register";
import Login from "./pages/Login";
import AdminLoginAttempts from "./pages/AdminLoginAttempts";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import MfaVerify from "./pages/MfaVerify";
import MfaSetup from "./pages/MfaSetup";
import BackupCodes from "./pages/BackupCodes";

export default function App() {
  return (
    <BrowserRouter>
      <header
        style={{
          padding: "12px 24px",
          borderBottom: "1px solid #444",
          marginBottom: 24,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontFamily: "system-ui",
        }}
      >
        <span>Secure Login System</span>
        <nav style={{ display: "flex", gap: 12 }}>
          <Link to="/">Home</Link>
          <Link to="/register">Register</Link>
          <Link to="/login">Login</Link>
          <Link to="/forgot-password">Forgot Password</Link>
          <Link to="/mfa/setup">MFA Setup</Link>
          <Link to="/backup-codes">Backup Codes</Link>
          <Link to="/admin/login-attempts">Admin</Link>
        </nav>
      </header>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/admin/login-attempts"
          element={<AdminLoginAttempts />}
        />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/mfa-verify" element={<MfaVerify />} />
        <Route path="/mfa/setup" element={<MfaSetup />} />
        <Route path="/backup-codes" element={<BackupCodes />} />
      </Routes>
    </BrowserRouter>
  );
}
