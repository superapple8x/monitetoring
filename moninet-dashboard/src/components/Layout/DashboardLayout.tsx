import React, { ReactNode } from "react";

interface DashboardLayoutProps {
  children: ReactNode;
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  return (
    <div className="flex flex-col min-h-screen bg-gray-100">
      <header className="bg-gray-800 text-white p-4 shadow-md">
        <h1 className="text-xl font-semibold">Network Monitoring Dashboard</h1>
      </header>
      <main className="flex-grow p-4 container mx-auto">{children}</main>
      <footer className="bg-gray-700 text-white text-center p-3 text-sm">
        &copy; {new Date().getFullYear()} MoniNet Dashboard
      </footer>
    </div>
  );
};

export default DashboardLayout;