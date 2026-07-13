import React from 'react';
import { NavLink } from 'react-router-dom';
import { Activity, UploadCloud, PieChart, Settings, Shield, Radio } from 'lucide-react';
import { motion } from 'framer-motion';

const Sidebar = () => {
  const links = [
    { name: 'Dashboard', path: '/dashboard', icon: <Activity size={20} /> },
    { name: 'Upload', path: '/upload', icon: <UploadCloud size={20} /> },
    { name: 'Live Capture', path: '/live', icon: <Radio size={20} /> },
    { name: 'Analysis', path: '/analysis', icon: <PieChart size={20} /> },
    { name: 'Settings', path: '/settings', icon: <Settings size={20} /> },
  ];

  return (
    <motion.div 
      initial={{ x: -250 }}
      animate={{ x: 0 }}
      className="w-64 bg-dark-800 border-r border-dark-700 flex flex-col shadow-2xl relative z-10"
    >
      <div className="p-6 flex items-center space-x-3 text-white font-bold text-xl border-b border-dark-700">
        <Shield size={28} className="text-accent drop-shadow-[0_0_8px_rgba(34,197,94,0.8)]" />
        <span className="tracking-wide">PacketLens<span className="text-accent">AI</span></span>
      </div>
      <nav className="flex-1 px-4 py-6 space-y-2">
        {links.map((link) => (
          <NavLink
            key={link.name}
            to={link.path}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-300 cursor-pointer ${
                isActive
                  ? 'bg-dark-700/50 text-accent font-medium border border-accent/20 shadow-[0_0_15px_rgba(34,197,94,0.15)]'
                  : 'text-slate-400 hover:bg-dark-700 hover:text-white'
              }`
            }
          >
            {link.icon}
            <span className="font-mono text-sm tracking-wider uppercase">{link.name}</span>
          </NavLink>
        ))}
      </nav>
      <div className="p-6 border-t border-dark-700 text-xs text-slate-500 text-center font-mono uppercase tracking-widest">
        SOC_TERMINAL_V1
      </div>
    </motion.div>
  );
};

export default Sidebar;
