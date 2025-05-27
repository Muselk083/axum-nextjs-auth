# Your Cyber Profile Project - Rust Axum + Next.js OAuth

![Cyberpunk Theme](https://img.shields.io/badge/theme-cyberpunk-00ff41?style=flat)
![Tech Stack](https://img.shields.io/badge/stack-Rust%20Axum%20+%20Next.js-ff006e?style=flat)

<!-- [![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](link-to-build-status) -->

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## 🚀 Overview

This project provides a secure authentication service using Google OAuth, allowing users to manage their profiles

---

## ✨ Features

List the key features of your application. Use bullet points for readability.

- Google OAuth 2.0 Integration
- User session management
- Secure sign-in and sign-out
- User profile retrieval (name, email, avatar)
- CORS support for frontend integration

---

## 🛠️ Technologies Used

This project leverages a modern tech stack to provide a fast and secure experience:

- **Backend:** Rust (Axum framework)
- **Frontend:** Next.js (React)
- **Authentication:** Google OAuth 2.0
- **Session Management:** `DashMap` (in-memory for demonstration purposes)
- **Dependency Management:** Cargo (Rust), npm/yarn (Node.js)

---

## ⚙️ Setup and Installation

Provide clear, step-by-step instructions on how to get your project up and running locally.

### Prerequisites

- Rust & Cargo
- Node.js & npm/yarn (for the frontend)
- Google Cloud Project with OAuth 2.0 credentials (Client ID, Client Secret)

### 🚀Backend Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo.git](https://github.com/your-username/your-repo.git)
    cd your-repo/backend-directory # Adjust if your backend is in a subfolder
    ```
2.  **Create a `.env` file:**
    ```
    GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
    GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
    REDIRECT_URL=http://localhost:8080/auth/google/callback
    ```
    _Replace `YOUR_GOOGLE_CLIENT_ID` and `YOUR_GOOGLE_CLIENT_SECRET` with your actual Google OAuth credentials._
3.  **Run the backend:**
    ```bash
    cargo run
    ```
    The backend server will start on `http://localhost:8080`.

### 🚀Frontend Setup

1.  **Navigate to the frontend directory:**
    ```bash
    cd ../frontend-directory # Adjust path as necessary
    ```
2.  **Install dependencies:**
    ```bash
    npm install # or yarn install
    ```
3.  **Run the frontend:**
    ```bash
    npm run dev # or yarn dev
    ```
    The frontend application will typically run on `http://localhost:3000`.

---

### 🔧 Environment Variables

- backend/.env

```bash
GOOGLE_CLIENT_ID=ClientIDHere.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=SecretKeyHere
AUTH_URL=http://localhost:3000/auth/google
TOKEN_URL=http://localhost:3000/auth/google/callback
# PORT=3000 //example port for the backend server
```

---

### 🌐 Endpoints

| Route                   | Method | Description                                                                              |
| :---------------------- | :----- | :--------------------------------------------------------------------------------------- |
| `/auth/google`          | `GET`  | Initiates the Google OAuth authentication flow.                                          |
| `/auth/google/callback` | `GET`  | Handles the OAuth callback from Google, setting the user session.                        |
| `/auth/signout`         | `GET`  | Destroys the current user session and logs out.                                          |
| `/api/user`             | `GET`  | Retrieves information about the currently authenticated user (requires a valid session). |

---

## 🚧 Future Improvements

- **Persistent Sessions:** Implement database integration (e.g., PostgreSQL, Redis) for durable user sessions instead of in-memory `DashMap`.
- **User Profile Editing:** Add endpoints and frontend functionality for users to update their skills, bio, etc.
- **Error Handling:** Enhance error handling and provide more specific error messages to the client.
- **Live Chat Integration:** Implement real-time chat functionality for user communication or support.
- **Testing:** Add unit and integration tests for both backend and frontend.

---

## 🤝 Contributing

Instructions on how others can contribute to your project.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
