// frontend/src/app/api/session/route.ts
import { NextResponse } from "next/server";

export async function GET() {
  const response = await fetch("http://localhost:8080/protected", {
    credentials: "include",
  });

  if (!response.ok) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }

  const data = await response.json();
  return NextResponse.json(data);
}
