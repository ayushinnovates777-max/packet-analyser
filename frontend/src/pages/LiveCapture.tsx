import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Activity, Wifi, WifiOff } from 'lucide-react';
import { getWsUrl } from '../config';

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  UDP: '#8b5cf6',
  HTTP: '#f59e0b',
  HTTPS: '#f97316',
  DNS: '#ec4899',
  ARP: '#06b6d4',
  ICMP: '#22c55e',
  TLS: '#a78bfa',
};

const LiveCapture = () => {
  const [packets, setPackets] = useState<any[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [expandedPacket, setExpandedPacket] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const packetsRef = useRef<any[]>([]); // To avoid dependency issues in ws.onmessage
  const pausedRef = useRef(false);

  useEffect(() => {
    pausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const connect = () => {
    if (ws.current) return;
    setErrorMsg(null);
    ws.current = new WebSocket(getWsUrl('/live/ws'));
    
    ws.current.onopen = () => setIsConnected(true);
    
    ws.current.onclose = () => {
      setIsConnected(false);
      ws.current = null;
    };
    
    ws.current.onerror = (err) => {
      console.error("WebSocket error:", err);
    };
    
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'error') {
        setErrorMsg(data.message);
        disconnect();
        return;
      }

      if (pausedRef.current) return;
      
      data.id = Math.random().toString(36).substr(2, 9);
      
      packetsRef.current = [data, ...packetsRef.current].slice(0, 100); // Keep last 100
      setPackets([...packetsRef.current]);
    };
  };

  const disconnect = () => {
    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
    setIsConnected(false);
  };

  const toggleConnection = () => {
    if (isConnected) {
      disconnect();
    } else {
      connect();
    }
  };

  return (
    <div className="space-y-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight font-sans flex items-center space-x-3">
            <Activity className={isConnected && !isPaused ? "text-accent animate-pulse" : "text-slate-500"} size={32} />
            <span>LIVE_CAPTURE</span>
          </h1>
          <p className="text-slate-400 mt-1 font-mono text-sm uppercase tracking-wider">
            Real-time interface packet sniffing
          </p>
        </div>
        
        <div className="flex space-x-4">
          <button 
            onClick={() => setIsPaused(!isPaused)}
            disabled={!isConnected}
            className={`px-4 py-2 font-mono text-sm rounded-lg border transition-colors ${
              !isConnected ? 'opacity-50 cursor-not-allowed border-dark-700 text-slate-500' :
              isPaused ? 'bg-amber-500/10 border-amber-500/30 text-amber-500' : 'bg-dark-800 border-dark-700 text-slate-300 hover:text-white hover:border-slate-500'
            }`}
          >
            {isPaused ? 'RESUME' : 'PAUSE_FEED'}
          </button>
          
          <button 
            onClick={toggleConnection}
            className={`flex items-center space-x-2 px-4 py-2 font-mono text-sm rounded-lg border transition-colors ${
              isConnected 
                ? 'bg-rose-500/10 border-rose-500/30 text-rose-500 hover:bg-rose-500/20' 
                : 'bg-accent/10 border-accent/30 text-accent hover:bg-accent/20'
            }`}
          >
            {isConnected ? <WifiOff size={16} /> : <Wifi size={16} />}
            <span>{isConnected ? 'DISCONNECT' : 'CONNECT'}</span>
          </button>
        </div>
      </div>

      {/* Terminal View */}
      <div className="flex-1 bg-black rounded-xl border border-dark-700 p-4 font-mono text-xs overflow-hidden relative shadow-2xl flex flex-col">
        <div className="absolute top-0 left-0 right-0 h-8 bg-dark-900 border-b border-dark-700 flex items-center px-4 space-x-2">
          <Terminal size={14} className="text-slate-500" />
          <span className="text-slate-500 uppercase tracking-widest">{getWsUrl('/live/ws')}</span>
        </div>
        
        <div className="mt-8 flex-1 overflow-hidden relative">
          {!isConnected && packets.length === 0 && !errorMsg ? (
             <div className="absolute inset-0 flex items-center justify-center text-slate-600 uppercase tracking-widest">
               [ NOT CONNECTED TO SOCKET ]
             </div>
          ) : errorMsg ? (
             <div className="absolute inset-0 flex flex-col items-center justify-center text-rose-500 uppercase tracking-widest text-center px-10">
               <span className="mb-2">⚠️ CAPTURE ERROR ⚠️</span>
               <span className="text-sm text-slate-400 font-sans normal-case max-w-lg">{errorMsg}</span>
             </div>
          ) : (
             <div className="absolute inset-0 overflow-y-auto custom-scrollbar flex flex-col-reverse p-2">
                <AnimatePresence>
                  {packets.map((pkt) => {
                    const color = PROTOCOL_COLORS[pkt.protocol.split('v')[0]] || '#64748b'; // Handle TLSv1.2 etc
                    const isExpanded = expandedPacket === pkt.id;
                    
                    return (
                      <React.Fragment key={pkt.id}>
                        <motion.div 
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          onClick={() => setExpandedPacket(isExpanded ? null : pkt.id)}
                          className={`py-1 border-b border-dark-800/30 hover:bg-dark-900/50 transition-colors flex space-x-4 items-center cursor-pointer ${isExpanded ? 'bg-dark-900/80' : ''}`}
                        >
                          <span className="text-slate-600 shrink-0 w-24">[{new Date(pkt.timestamp * 1000).toISOString().split('T')[1].slice(0, -1)}]</span>
                          <span 
                            className="shrink-0 w-16 text-center font-bold"
                            style={{ color }}
                          >
                            {pkt.protocol}
                          </span>
                          <span className="text-slate-400 shrink-0 w-36 truncate text-right">{pkt.src_ip}</span>
                          <span className="text-slate-600 shrink-0">→</span>
                          <span className="text-slate-400 shrink-0 w-36 truncate">{pkt.dst_ip}</span>
                          <span className="text-slate-500 shrink-0 w-16 text-right">{pkt.length} B</span>
                        </motion.div>
                        
                        {isExpanded && pkt.summary && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="bg-black border-b border-dark-800/30 overflow-hidden"
                          >
                            <div className="p-4 pl-32 border-l-2" style={{ borderColor: color }}>
                               <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Decoded Frame Summary</p>
                               <pre className="text-slate-400 text-[10px] whitespace-pre-wrap">{pkt.summary}</pre>
                            </div>
                          </motion.div>
                        )}
                      </React.Fragment>
                    );
                  })}
                </AnimatePresence>
             </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LiveCapture;
