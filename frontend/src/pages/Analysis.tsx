import React, { useEffect, useState, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, CheckCircle2, Shield, AlertTriangle, ArrowRight, Search, Download, Loader2, Sparkles, Terminal } from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { API_URL } from '../config';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

const PROTOCOL_COLORS: Record<string, string> = {
  TCP:  '#3b82f6',
  UDP:  '#8b5cf6',
  HTTP: '#f59e0b',
  HTTPS:'#f97316',
  DNS:  '#ec4899',
  ARP:  '#06b6d4',
  ICMP: '#22c55e',
  DATA: '#64748b',
  TLS:  '#a78bfa',
};
const DEFAULT_COLORS = ['#22C55E','#3b82f6','#f59e0b','#ec4899','#8b5cf6','#06b6d4','#f97316','#84cc16'];

const ThreatCard = ({ threat, index }: { threat: any; index: number }) => {
  // Simple regex to extract IP from threat evidence
  const ipMatch = threat.evidence?.match(/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/);
  const maliciousIp = ipMatch ? ipMatch[0] : null;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className="bg-dark-800 border-l-4 border-rose-500 rounded-r-xl p-5 shadow-lg flex items-start space-x-4 border border-y-dark-700 border-r-dark-700"
    >
      <div className="p-2 bg-rose-500/10 rounded-lg text-rose-500 shrink-0">
        <ShieldAlert size={24} />
      </div>
      <div className="w-full">
        <div className="flex items-center space-x-2">
          <h4 className="text-white font-mono uppercase tracking-wider text-sm">{threat.description}</h4>
          <span className="px-2.5 py-0.5 rounded-full text-xs font-mono uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/30">
            {threat.severity}
          </span>
        </div>
        <p className="text-slate-400 mt-2 text-sm font-mono">{threat.evidence}</p>
        <div className="mt-3 bg-dark-900/50 p-3 rounded-lg border border-dark-700 flex items-start space-x-2">
          <ArrowRight size={16} className="text-accent mt-0.5 shrink-0" />
          <p className="text-sm text-slate-300 font-mono"><span className="text-slate-500">RECOMMENDATION:</span> {threat.recommendation}</p>
        </div>
        
        {/* Smart AI Remediation */}
        {maliciousIp && (
          <div className="mt-4 pt-4 border-t border-dark-700">
            <h5 className="text-xs font-mono text-slate-500 uppercase tracking-widest mb-2 flex items-center">
              <Sparkles size={12} className="text-accent mr-1.5"/> AI Remediation Generated
            </h5>
            <div className="bg-black p-3 rounded-lg border border-dark-700 font-mono text-xs text-emerald-400 flex justify-between items-center group">
              <div className="flex items-center space-x-2">
                <Terminal size={14} className="text-slate-600" />
                <code>iptables -A INPUT -s {maliciousIp} -j DROP</code>
              </div>
              <button 
                onClick={() => navigator.clipboard.writeText(`iptables -A INPUT -s ${maliciousIp} -j DROP`)} 
                className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-white transition-all bg-dark-800 px-2 py-1 rounded"
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
};

const StatCard = ({ label, value, sub }: { label: string; value: string; sub?: string }) => (
  <div className="bg-dark-800 p-6 rounded-2xl border border-dark-700 shadow-lg hover:border-accent/30 transition-all">
    <p className="text-slate-400 text-xs font-mono uppercase tracking-wider">{label}</p>
    <p className="text-3xl font-bold text-white mt-2 font-mono">{value}</p>
    {sub && <p className="text-xs text-slate-500 font-mono mt-1">{sub}</p>}
  </div>
);

const Analysis = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const state = location.state as { captureId?: number };

  const [capture, setCapture] = useState<any>(null);
  const [protocols, setProtocols] = useState<any[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [packets, setPackets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'packets'>('overview');
  const [expandedPacket, setExpandedPacket] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = async (captureId: number) => {
    const [sumRes, threatRes, pktRes] = await Promise.all([
      fetch(`${API_URL}/captures/${captureId}`),
      fetch(`${API_URL}/captures/${captureId}/threats`),
      fetch(`${API_URL}/captures/${captureId}/packets?limit=200`),
    ]);
    const sumData = await sumRes.json();
    const threatData = await threatRes.json();
    const pktData = await pktRes.json();

    setCapture(sumData.capture);
    setProtocols(sumData.protocols || []);
    setThreats(Array.isArray(threatData) ? threatData : []);
    setPackets(pktData.packets || []);
    return sumData.capture?.status;
  };

  useEffect(() => {
    if (!state?.captureId) return;
    const captureId = state.captureId;

    const init = async () => {
      try {
        const status = await fetchAll(captureId);
        setLoading(false);

        // If still processing, poll every 2 seconds until done
        if (status === 'processing') {
          pollRef.current = setInterval(async () => {
            try {
              const s = await fetchAll(captureId);
              if (s !== 'processing') {
                clearInterval(pollRef.current!);
              }
            } catch { /* keep polling */ }
          }, 2000);
        }
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    };

    init();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [state]);

  const exportData = (format: 'json' | 'csv' | 'pdf') => {
    if (format === 'json') {
      const exportObj = { capture, protocols, threats };
      const blob = new Blob([JSON.stringify(exportObj, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `packetlens_export_${capture.id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else if (format === 'csv') {
      const headers = ['No.', 'Time', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Length'];
      const rows = packets.map(p => [
        p.packet_number, p.timestamp, p.src_ip || '', p.src_port || '', p.dst_ip || '', p.dst_port || '', p.protocol, p.length
      ].join(','));
      const csv = [headers.join(','), ...rows].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `packetlens_packets_${capture.id}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } else if (format === 'pdf') {
      const doc = new jsPDF();
      let yPos = 20;
      
      // Title & Metadata
      doc.setFontSize(22);
      doc.setTextColor(40, 40, 40);
      doc.text('PacketLens AI - Security Report', 14, yPos);
      yPos += 12;
      
      doc.setFontSize(11);
      doc.setTextColor(100, 100, 100);
      doc.text(`Target File: ${capture.filename}`, 14, yPos);
      yPos += 7;
      doc.text(`Analysis Date: ${new Date(capture.upload_time).toLocaleString()}`, 14, yPos);
      yPos += 7;
      doc.text(`Overall Risk Score: ${capture.risk_score}/100`, 14, yPos);
      yPos += 15;
      
      // Executive Summary
      if (capture.ai_summary) {
        doc.setFontSize(14);
        doc.setTextColor(20, 20, 20);
        doc.text('Executive AI Summary', 14, yPos);
        yPos += 8;
        
        doc.setFontSize(10);
        doc.setTextColor(60, 60, 60);
        const splitText = doc.splitTextToSize(capture.ai_summary, 180);
        doc.text(splitText, 14, yPos);
        yPos += splitText.length * 5 + 12;
      }
      
      // Threat Detections
      if (threats && threats.length > 0) {
        doc.setFontSize(14);
        doc.setTextColor(20, 20, 20);
        doc.text('Detected Threats & Anomalies', 14, yPos);
        yPos += 6;
        
        const threatData = threats.map(t => [t.severity, t.category, t.description, t.recommendation]);
        autoTable(doc, {
          startY: yPos,
          head: [['Severity', 'Category', 'Description', 'Recommendation']],
          body: threatData,
          theme: 'grid',
          headStyles: { fillColor: [244, 63, 94] }, // Rose-500
          styles: { fontSize: 9 },
          columnStyles: { 3: { cellWidth: 70 } }
        });
        yPos = (doc as any).lastAutoTable.finalY + 15;
      } else {
        doc.setFontSize(12);
        doc.setTextColor(34, 197, 94); // Green-500
        doc.text('No critical threats detected. Traffic appears nominal.', 14, yPos);
        yPos += 15;
      }
      
      // Protocol Distribution
      if (protocols && protocols.length > 0) {
        // Check page boundary
        if (yPos > 240) {
          doc.addPage();
          yPos = 20;
        }
        doc.setFontSize(14);
        doc.setTextColor(20, 20, 20);
        doc.text('Protocol Distribution', 14, yPos);
        yPos += 6;
        
        const protoData = protocols.map(p => [p.protocol_name, p.packet_count.toLocaleString()]);
        autoTable(doc, {
          startY: yPos,
          head: [['Protocol', 'Packet Count']],
          body: protoData,
          theme: 'striped',
          headStyles: { fillColor: [15, 23, 42] } // Slate-900
        });
      }
      
      doc.save(`packetlens_report_${capture.id}.pdf`);
    }
  };

  if (!state?.captureId) {
    return (
      <div className="flex flex-col items-center justify-center py-32 space-y-6">
        <div className="bg-dark-800 p-8 rounded-full border border-dark-700 shadow-xl">
          <Search size={64} className="text-dark-700" />
        </div>
        <div className="text-center space-y-2">
          <h2 className="text-2xl font-bold text-white font-sans tracking-tight">No Capture Selected</h2>
          <p className="text-slate-400 font-mono text-sm max-w-md mx-auto">
            Please select a packet capture from the dashboard or upload a new PCAP file to view its detailed analysis report.
          </p>
        </div>
        <div className="flex space-x-4 pt-4">
          <button onClick={() => navigate('/dashboard')} className="px-6 py-2.5 bg-dark-800 border border-dark-700 rounded-lg text-white font-mono text-sm hover:border-slate-500 transition-colors">
            Go to Dashboard
          </button>
          <button onClick={() => navigate('/upload')} className="px-6 py-2.5 bg-accent text-black font-bold rounded-lg font-mono text-sm hover:bg-accent/90 transition-colors">
            Upload PCAP
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-32 space-y-4">
        <Loader2 size={48} className="text-accent animate-spin" />
        <p className="text-accent font-mono animate-pulse uppercase tracking-widest text-sm">Loading analysis...</p>
      </div>
    );
  }

  if (!capture) {
    return (
      <div className="text-center py-20">
        <p className="text-rose-400 font-mono">Failed to load capture data.</p>
        <button onClick={() => navigate('/dashboard')} className="mt-4 text-accent font-mono text-sm underline">
          Back to Dashboard
        </button>
      </div>
    );
  }

  const isProcessing = capture.status === 'processing';

  const filteredPackets = packets.filter((pkt) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (pkt.src_ip && pkt.src_ip.toLowerCase().includes(q)) ||
      (pkt.dst_ip && pkt.dst_ip.toLowerCase().includes(q)) ||
      (pkt.protocol && pkt.protocol.toLowerCase().includes(q)) ||
      (pkt.src_port && pkt.src_port.toString().includes(q)) ||
      (pkt.dst_port && pkt.dst_port.toString().includes(q)) ||
      (pkt.packet_number && pkt.packet_number.toString().includes(q))
    );
  });

  const protocolColors = protocols.map((p, i) => PROTOCOL_COLORS[p.protocol_name] || DEFAULT_COLORS[i % DEFAULT_COLORS.length]);

  const protocolData = {
    labels: protocols.map((p) => p.protocol_name),
    datasets: [{
      data: protocols.map((p) => p.packet_count),
      backgroundColor: protocolColors.map(c => c + 'cc'),
      borderColor: protocolColors,
      borderWidth: 2,
    }],
  };

  const barData = {
    labels: protocols.map((p) => p.protocol_name),
    datasets: [{
      label: 'Packets',
      data: protocols.map((p) => p.packet_count),
      backgroundColor: protocolColors.map(c => c + '80'),
      borderColor: protocolColors,
      borderWidth: 1,
      borderRadius: 6,
    }],
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12">
      {/* Header */}
      <div className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight font-sans">ANALYSIS_REPORT</h1>
          <p className="text-slate-400 mt-1 font-mono text-sm uppercase tracking-wider">
            TARGET: <span className="text-accent">{capture.filename}</span>
          </p>
        </div>

        <div className="flex items-center space-x-4">
          {/* Export Dropdown */}
          {!isProcessing && (
            <div className="relative group">
              <button className="flex items-center space-x-2 bg-dark-800 border border-dark-700 hover:border-slate-500 px-4 py-3 rounded-xl transition-colors">
                <Download size={18} className="text-slate-400 group-hover:text-white" />
                <span className="text-slate-400 group-hover:text-white font-mono text-sm uppercase tracking-wider">Export</span>
              </button>
              <div className="absolute right-0 top-full mt-2 w-56 bg-dark-800 border border-dark-700 rounded-xl shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50 overflow-hidden">
                <button onClick={() => exportData('pdf')} className="w-full text-left px-4 py-3 text-sm font-mono text-slate-300 hover:bg-dark-700 hover:text-accent transition-colors">
                  Export Report (PDF)
                </button>
                <button onClick={() => exportData('json')} className="w-full text-left px-4 py-3 text-sm font-mono text-slate-300 hover:bg-dark-700 hover:text-accent transition-colors border-t border-dark-700">
                  Export Data (JSON)
                </button>
                <button onClick={() => exportData('csv')} className="w-full text-left px-4 py-3 text-sm font-mono text-slate-300 hover:bg-dark-700 hover:text-accent transition-colors border-t border-dark-700">
                  Export Packets (CSV)
                </button>
              </div>
            </div>
          )}

          <div className={`px-6 py-3 rounded-xl border flex items-center space-x-3 ${
            isProcessing ? 'bg-amber-500/10 border-amber-500/30' :
            capture.risk_score > 50 ? 'bg-rose-500/10 border-rose-500/30 shadow-[0_0_15px_rgba(244,63,94,0.15)]' :
            capture.risk_score > 0 ? 'bg-amber-500/10 border-amber-500/30' :
            'bg-accent/10 border-accent/30 shadow-[0_0_15px_rgba(34,197,94,0.15)]'
          }`}>
            {isProcessing
              ? <Loader2 className="text-amber-400 animate-spin" />
              : capture.risk_score > 50 ? <ShieldAlert className="text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.8)]" />
              : capture.risk_score > 0 ? <AlertTriangle className="text-amber-500" />
              : <Shield className="text-accent drop-shadow-[0_0_8px_rgba(34,197,94,0.8)]" />}
            <div>
              <p className="text-xs text-slate-400 font-mono uppercase tracking-wider">{isProcessing ? 'Status' : 'Risk Score'}</p>
              <p className={`text-2xl font-bold font-mono ${
                isProcessing ? 'text-amber-400' :
                capture.risk_score > 50 ? 'text-rose-500' :
                capture.risk_score > 0 ? 'text-amber-500' : 'text-accent'
              }`}>
                {isProcessing ? 'ANALYZING...' : `${capture.risk_score}/100`}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Processing banner */}
      {isProcessing && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-center space-x-3"
        >
          <Loader2 size={20} className="text-amber-400 animate-spin shrink-0" />
          <p className="text-amber-300 font-mono text-sm">
            Analysis is running in the background — this page will update automatically when complete.
          </p>
        </motion.div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-dark-700 space-x-8 font-mono text-sm uppercase tracking-wider">
        <button
          onClick={() => setActiveTab('overview')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'overview' ? 'border-accent text-accent' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
        >Overview</button>
        <button
          onClick={() => setActiveTab('packets')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'packets' ? 'border-accent text-accent' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
        >Packet Inspector</button>
      </div>

      {activeTab === 'overview' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
          {/* Executive AI Summary */}
          {!isProcessing && capture.ai_summary && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              className="bg-accent/5 border border-accent/20 p-6 rounded-2xl relative overflow-hidden"
            >
              <div className="absolute top-0 right-0 p-8 opacity-5">
                <Sparkles size={120} />
              </div>
              <div className="relative z-10">
                <h3 className="text-sm font-mono text-accent flex items-center space-x-2 uppercase tracking-wider mb-3">
                  <Sparkles size={16} />
                  <span>Executive Summary</span>
                </h3>
                <p className="text-slate-300 font-mono text-sm leading-relaxed max-w-4xl">
                  {capture.ai_summary}
                </p>
              </div>
            </motion.div>
          )}

          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Total Packets" value={capture.total_packets?.toLocaleString() ?? '—'} />
            <StatCard label="Total Bytes" value={formatBytes(capture.total_bytes ?? 0)} />
            <StatCard label="Protocols" value={protocols.length.toString()} sub={protocols.map(p => p.protocol_name).join(', ') || '—'} />
            <StatCard label="Threats" value={threats.length.toString()} sub={threats.length > 0 ? 'Detected' : 'Clean'} />
          </div>

          {isProcessing ? (
            <div className="bg-dark-800 border border-dark-700 rounded-2xl p-16 flex flex-col items-center justify-center space-y-4">
              <Loader2 size={40} className="text-accent animate-spin" />
              <p className="text-slate-400 font-mono text-sm uppercase tracking-widest animate-pulse">Parsing packets...</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Protocol Doughnut */}
              <div className="bg-dark-800 p-6 rounded-2xl border border-dark-700 shadow-lg">
                <h3 className="text-sm font-mono text-white mb-6 uppercase tracking-wider">Protocol Distribution</h3>
                <div className="h-64 flex items-center justify-center">
                  {protocols.length > 0 ? (
                    <Doughnut
                      data={protocolData}
                      options={{
                        maintainAspectRatio: false,
                        plugins: {
                          legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Fira Code', size: 11 }, padding: 12 } },
                          tooltip: { callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()} pkts` } },
                        },
                        cutout: '65%',
                      }}
                    />
                  ) : (
                    <p className="text-slate-500 font-mono text-sm">NO_PROTOCOL_DATA</p>
                  )}
                </div>
              </div>

              {/* Packet count bar chart */}
              <div className="bg-dark-800 p-6 rounded-2xl border border-dark-700 shadow-lg">
                <h3 className="text-sm font-mono text-white mb-6 uppercase tracking-wider">Packets per Protocol</h3>
                <div className="h-64">
                  {protocols.length > 0 ? (
                    <Bar
                      data={barData}
                      options={{
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                          x: { ticks: { color: '#64748b', font: { family: 'Fira Code', size: 10 } }, grid: { color: '#1e293b' } },
                          y: { ticks: { color: '#64748b', font: { family: 'Fira Code', size: 10 } }, grid: { color: '#1e293b' } },
                        },
                      }}
                    />
                  ) : (
                    <p className="text-slate-500 font-mono text-sm flex items-center justify-center h-full">NO_DATA</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Threats */}
          {!isProcessing && (
            <div className="space-y-4">
              <h3 className="text-sm font-mono text-white flex items-center space-x-2 uppercase tracking-wider">
                <span>Threat Detections</span>
                <span className="bg-dark-700 text-accent border border-accent/20 text-xs py-0.5 px-2.5 rounded-full">{threats.length}</span>
              </h3>
              {threats.length === 0 ? (
                <div className="bg-accent/5 border border-accent/20 rounded-2xl p-8 text-center flex flex-col items-center justify-center">
                  <CheckCircle2 size={48} className="text-accent mb-4 drop-shadow-[0_0_8px_rgba(34,197,94,0.8)]" />
                  <h4 className="text-lg font-mono text-white mb-2 uppercase tracking-wide">No threats detected</h4>
                  <p className="text-slate-400 max-w-md text-sm font-mono">Heuristics show nominal traffic patterns.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {threats.map((threat, idx) => <ThreatCard key={idx} threat={threat} index={idx} />)}
                </div>
              )}
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'packets' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          <div className="flex justify-between items-center bg-dark-800 p-4 rounded-xl border border-dark-700">
            <div className="relative w-72">
              <Search className="absolute left-3 top-2.5 text-slate-500" size={16} />
              <input
                type="text"
                placeholder="Search IPs, ports, protocols..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-10 pr-4 py-2 text-sm font-mono text-white focus:outline-none focus:border-accent/50 transition-colors"
              />
            </div>
            <p className="text-slate-500 font-mono text-xs">{filteredPackets.length} of {packets.length} packets</p>
          </div>

          {packets.length === 0 ? (
            <div className="bg-dark-800 border border-dark-700 rounded-2xl p-12 text-center">
              {isProcessing
                ? <><Loader2 size={32} className="text-accent animate-spin mx-auto mb-3" /><p className="text-slate-400 font-mono text-sm">Packets loading...</p></>
                : <p className="text-slate-500 font-mono text-sm">No packets found for this capture.</p>
              }
            </div>
          ) : (
            <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-dark-900 border-b border-dark-700">
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider w-16">No.</th>
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider w-28">Time</th>
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider">Source</th>
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider">Destination</th>
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider w-24">Protocol</th>
                    <th className="py-3 px-4 text-xs font-mono text-slate-400 uppercase tracking-wider w-20">Len</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-sm divide-y divide-dark-700">
                  {filteredPackets.map((pkt) => {
                    const color = PROTOCOL_COLORS[pkt.protocol] || '#64748b';
                    return (
                      <React.Fragment key={pkt.id}>
                        <tr
                          onClick={() => setExpandedPacket(expandedPacket === pkt.id ? null : pkt.id)}
                          className={`cursor-pointer transition-colors ${expandedPacket === pkt.id ? 'bg-dark-700/80' : 'hover:bg-dark-700/40'}`}
                        >
                          <td className="py-2.5 px-4 text-slate-500">{pkt.packet_number}</td>
                          <td className="py-2.5 px-4 text-slate-400 text-xs">{pkt.timestamp?.toFixed(4)}</td>
                          <td className="py-2.5 px-4 text-slate-300">{pkt.src_ip || '—'}{pkt.src_port ? `:${pkt.src_port}` : ''}</td>
                          <td className="py-2.5 px-4 text-slate-300">{pkt.dst_ip || '—'}{pkt.dst_port ? `:${pkt.dst_port}` : ''}</td>
                          <td className="py-2.5 px-4">
                            <span
                              className="px-2 py-0.5 rounded text-xs font-mono border"
                              style={{ color, borderColor: color + '50', backgroundColor: color + '18' }}
                            >
                              {pkt.protocol}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-slate-400">{pkt.length}</td>
                        </tr>
                        <AnimatePresence>
                          {expandedPacket === pkt.id && (
                            <motion.tr
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              className="bg-dark-900/60"
                            >
                              <td colSpan={6} className="p-0">
                                <div className="p-5 border-b border-dark-700">
                                  <h4 className="text-accent text-xs uppercase tracking-widest mb-3">Decoded Packet Tree</h4>
                                  <pre className="text-slate-300 bg-dark-900 border border-dark-700 p-4 rounded-lg overflow-x-auto text-xs whitespace-pre-wrap leading-relaxed shadow-inner max-h-72 overflow-y-auto custom-scrollbar">
                                    {pkt.summary}
                                  </pre>
                                </div>
                              </td>
                            </motion.tr>
                          )}
                        </AnimatePresence>
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};

export default Analysis;
