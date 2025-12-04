import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import Home from "./pages/Home";
import Register from "./pages/Register";
import Login from "./pages/Login";
import AdminLoginAttempts from "./pages/AdminLoginAttempts";

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
      </Routes>
    </BrowserRouter>
  );
}
