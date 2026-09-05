import "./globals.css";

export const metadata = {
  title: "Sentinel Security",
  description: "AI-driven attack-path analysis and cross-tool correlation",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
