"use client";
import { useEffect, useState } from "react";
import { GlowText } from "@/components/ui/GlowText";
import { useRouter } from "next/navigation";
import Image from "next/image";

// Define the backend URL using the environment variable
const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8080";
if (!BACKEND_URL) {
  throw new Error("NEXT_PUBLIC_BACKEND_URL is not defined");
}

interface UserData {
  name: string;
  email: string;
  avatar: string;
  skills?: string[];
  bio?: string;
}

export default function Portfolio() {
  const [user, setUser] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/user`, {
          credentials: "include",
        });

        if (res.status === 401) {
          setIsAuthenticated(false);
          return;
        }

        if (!res.ok) throw new Error("Failed to fetch user");

        const data = await res.json();
        setUser({
          ...data.user,
          skills: data.user.skills || [],
          bio: data.user.bio || "Cyber security enthusiast",
        });
        setIsAuthenticated(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
        setIsAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  const handleSignOut = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/auth/signout`, {
        method: "GET",
        credentials: "include",
      });

      if (response.ok) {
        router.push("/");
        // Add this line to reload the page after navigation
        window.location.reload();
      }
    } catch (error) {
      console.error("Sign out failed:", error);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      // Redirect to backend OAuth endpoint
      window.location.href = `${BACKEND_URL}/auth/google`;
    } catch (error) {
      console.error("Google login failed:", error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <GlowText className="text-cyan-400 animate-pulse">
          Loading cyber profile...
        </GlowText>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-black text-green-400">
        <GlowText as="h1" className="text-4xl mb-8">
          ACCESS_DENIED
        </GlowText>
        <p className="mb-6">You must authenticate to access this terminal</p>
        <p
          onClick={handleGoogleLogin}
          className="cyber-button px-6 py-3 font-mono uppercase tracking-wider cursor-pointer"
        >
          INITIATE_GOOGLE_AUTH
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <GlowText className="text-red-400">ERROR: {error}</GlowText>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono p-8">
      <header className="border-b border-cyan-500 pb-6 mb-8 flex justify-between items-center">
        <div>
          <GlowText as="h1" className="text-4xl mb-2">
            {user?.name || "User"}
          </GlowText>
          <div className="flex items-center gap-4">
            <Image
              src={user?.avatar || "/default-avatar.png"}
              alt={user?.name || "User avatar"}
              width={48}
              height={48}
              className="w-12 h-12 rounded-full border-2 border-cyan-500"
            />
            <span className="text-cyan-300">{user?.email || "No email"}</span>
          </div>
        </div>
        <button
          onClick={handleSignOut}
          className="cyber-button-destructive px-4 py-2 text-sm cursor-pointer"
        >
          ::/sign_out
        </button>
      </header>

      <section className="mb-10">
        <GlowText as="h2" className="text-2xl mb-4">
          ::/whoami
        </GlowText>
        <p className="text-green-300 mb-6">{user?.bio || "No bio available"}</p>

        <GlowText as="h3" className="text-xl mb-3">
          ::/skills
        </GlowText>
        <div className="flex flex-wrap gap-2">
          {(user?.skills || []).length > 0 ? (
            (user?.skills || []).map((skill) => (
              <span
                key={skill}
                className="px-3 py-1 bg-gray-900 text-cyan-400 rounded-full border border-cyan-800"
              >
                {skill}
              </span>
            ))
          ) : (
            <span className="text-gray-500">No skills listed</span>
          )}
        </div>
      </section>

      <section>
        <GlowText as="h2" className="text-2xl mb-4">
          ::/system_status
        </GlowText>
        <div className="flex items-center gap-4 text-green-400">
          <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
          <span>AUTHENTICATED</span>
        </div>
      </section>
    </div>
  );
}
