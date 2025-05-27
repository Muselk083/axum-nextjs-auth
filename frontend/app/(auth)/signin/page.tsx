import { Login1 } from "@/components/auth/Login1";
import logo from "@/public/rust-logo.png";

export default function LoginPage() {
  return (
    <Login1
      heading="Welcome Back"
      googleText="Continue with Google"
      logo={{
        url: "/rust-logo.jpg",
        src: logo.src ?? "/rust-logo.png",
        alt: "Rust Logo",
        title: "Rust Logo",
      }}
    />
  );
}
