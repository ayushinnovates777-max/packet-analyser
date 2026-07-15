import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

const Layout = () => {
  return (
    <div className="flex h-screen bg-dark-900 text-slate-300 font-sans overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-8 bg-dark-900">
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
