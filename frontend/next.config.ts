/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: "http", // Use http for localhost if you use it for image serving later
        hostname: "localhost", // Example for localhost images, if you have them
      },
      {
        protocol: "https", // Google images are always https
        hostname: "lh3.googleusercontent.com", // <--- Add this line
        port: "", // Leave empty for default ports (80/443)
        pathname: "/a/**", // This path is common for Google profile pictures
      },
      // Add other remote image domains here if needed
    ],
  },
};

module.exports = nextConfig;
