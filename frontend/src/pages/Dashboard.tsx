import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldAlert, BarChart3, Network, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { API_URL } from '../config';

const StatCard = ({ title, value, icon, delay, highlight = false }: { title: string; value: string | number; icon: React.ReactNode; delay: number; highlight?: boolean }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ delay }}
    className={`bg-dark-800 p-6 rounded-2xl border ${highlight ? 'border-accent/30 shadow-[0_0_15px_rgba(34,197,94,0.1)]' : 'border-dark-700 shadow-lg'} flex items-center space-x-4 hover:border-accent/50 transition-all`}
  >
    <div className={`p-4 rounded-xl ${highlight ? 'bg-accent/10 text-accent' : 'bg-dark-900 text-slate-400'}`}>
      {icon}
    </div>
    <div>
      <h4 className="text-slate-400 text-xs font-mono uppercase tracking-wider">{title}</h4>
      <p className={`text-2xl font-bold mt-1 ${highlight ? 'text-accent' : 'text-white'}`}>{value}</p>
    </div>
  </motion.div>
);

const Dashboard = () => {
  const [captures, setCaptures] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetch(`${API_URL}/captures/`)
      .then(res => res.json())
      .then(data => {
        setCaptures(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  const totalPackets = captures.reduce((acc, curr) => acc + (curr.total_packets || 0), 0);
  const criticalThreats = captures.filter(c => c.risk_score > 50).length;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight font-sans">SOC_DASHBOARD</h1>
        <p className="text-accent mt-1 font-mono text-sm uppercase tracking-widest">System overview and latest security insights.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <StatCard title="Total Captures" value={captures.length} icon={<Activity size={24} />} delay={0.1} />
        <StatCard title="Critical Captures" value={criticalThreats} icon={<ShieldAlert size={24} />} delay={0.2} highlight={criticalThreats > 0} />
        <StatCard title="Packets Analyzed" value={(totalPackets / 1000).toFixed(1) + 'k'} icon={<BarChart3 size={24} />} delay={0.3} />
        <StatCard title="Sensors Active" value="1" icon={<Network size={24} />} delay={0.4} />
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-mono text-white uppercase tracking-widest border-b border-dark-700 pb-2">Recent Analysis Tasks</h3>
        
        {loading ? (
           <div className="text-center py-12 text-slate-500 font-mono animate-pulse">LOADING_DATA...</div>
        ) : captures.length === 0 ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="bg-dark-800 p-12 rounded-2xl border border-dark-700 shadow-lg flex items-center justify-center"
          >
            <div className="text-center">
              <Activity size={48} className="mx-auto text-dark-700 mb-4" />
              <h3 className="text-xl font-medium text-slate-300 font-mono">NO_DATA_FOUND</h3>
              <p className="text-slate-500 mt-2 font-mono text-sm">Upload a PCAP file to start analyzing traffic.</p>
              <button 
                onClick={() => navigate('/upload')}
                className="mt-6 px-6 py-2 bg-accent/10 text-accent border border-accent/30 rounded font-mono text-sm uppercase tracking-wider hover:bg-accent/20 transition-all"
              >
                Go to Upload
              </button>
            </div>
          </motion.div>
        ) : (
          <div className="bg-dark-800 rounded-2xl border border-dark-700 overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-dark-900 border-b border-dark-700">
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">File</th>
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">Time</th>
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">Packets</th>
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">Risk Score</th>
                  <th className="py-4 px-6 text-xs font-mono text-slate-400 uppercase tracking-wider">Action</th>
                </tr>
              </thead>
              <tbody>
                {captures.slice(0, 5).map((cap, i) => (
                  <motion.tr 
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 * i }}
                    key={cap.id} 
                    className="border-b border-dark-700 hover:bg-dark-700/50 transition-colors"
                  >
                    <td className="py-4 px-6 text-sm text-white font-medium">{cap.filename}</td>
                    <td className="py-4 px-6 text-sm text-slate-400">{new Date(cap.upload_time).toLocaleString()}</td>
                    <td className="py-4 px-6">
                      <span className={`px-2.5 py-1 text-xs rounded font-mono uppercase tracking-wider ${cap.status === 'completed' ? 'bg-accent/10 text-accent border border-accent/20' : 'bg-amber-500/10 text-amber-500 border border-amber-500/20'}`}>
                        {cap.status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-sm text-slate-300 font-mono">{cap.total_packets}</td>
                    <td className="py-4 px-6 text-sm font-mono">
                      <span className={`${cap.risk_score > 50 ? 'text-rose-500' : 'text-accent'}`}>{cap.risk_score}</span> / 100
                    </td>
                    <td className="py-4 px-6 text-sm">
                       <button 
                         onClick={() => navigate('/analysis', { state: { captureId: cap.id }})}
                         className="flex items-center space-x-1 text-slate-400 hover:text-accent transition-colors"
                       >
                         <span className="font-mono text-xs uppercase tracking-wider">View</span>
                         <ArrowRight size={14} />
                       </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
