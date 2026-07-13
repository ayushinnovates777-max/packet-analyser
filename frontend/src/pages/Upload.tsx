import React, { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, File, AlertCircle, CheckCircle2, Loader2, ShieldCheck, ShieldAlert, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { uploadPcap } from '../services/api';
import { API_URL } from '../config';

// ── Constants ──────────────────────────────────────────────────────────────
const MAX_SIZE_BYTES = 50 * 1024 * 1024;   // 50 MB
const MIN_SIZE_BYTES = 24;                  // smallest valid pcap header

const ALLOWED_EXTENSIONS = new Set(['.pcap', '.pcapng', '.cap']);

// Magic bytes for all pcap/pcapng variants
const MAGIC_SIGNATURES: { label: string; bytes: number[] }[] = [
  { label: 'PCAP (LE)',     bytes: [0xa1, 0xb2, 0xc3, 0xd4] },
  { label: 'PCAP (BE)',     bytes: [0xd4, 0xc3, 0xb2, 0xa1] },
  { label: 'PCAP-ns (LE)',  bytes: [0xa1, 0xb2, 0x3c, 0x4d] },
  { label: 'PCAP-ns (BE)', bytes: [0x4d, 0x3c, 0xb2, 0xa1] },
  { label: 'PCAPNG',        bytes: [0x0a, 0x0d, 0x0d, 0x0a] },
];

const DANGEROUS_INNER_EXTS = new Set([
  'exe','dll','bat','cmd','sh','py','js','vbs',
  'ps1','php','rb','pl','jar','msi','com','scr',
]);

const ANALYSIS_STAGES = [
  'Uploading file...',
  'Validating packet signatures...',
  'Parsing protocol layers...',
  'Extracting flow metadata...',
  'Running threat heuristics...',
  'Building session graph...',
  'Finalizing analysis report...',
];

// ── Helpers ────────────────────────────────────────────────────────────────
async function readMagicBytes(file: File, n: number): Promise<Uint8Array> {
  const slice = file.slice(0, n);
  const buf   = await slice.arrayBuffer();
  return new Uint8Array(buf);
}

function matchesMagic(bytes: Uint8Array): { ok: boolean; label?: string } {
  for (const sig of MAGIC_SIGNATURES) {
    if (sig.bytes.every((b, i) => bytes[i] === b)) {
      return { ok: true, label: sig.label };
    }
  }
  return { ok: false };
}

interface SecurityCheck {
  label: string;
  status: 'pass' | 'fail' | 'pending';
  detail?: string;
}

// ── Component ──────────────────────────────────────────────────────────────
const Upload = () => {
  const navigate  = useNavigate();
  const [dragActive, setDragActive]           = useState(false);
  const [file, setFile]                       = useState<File | null>(null);
  const [uploading, setUploading]             = useState(false);
  const [uploadProgress, setUploadProgress]   = useState(0);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [stage, setStage]                     = useState('');
  const [phase, setPhase]                     = useState<'idle'|'uploading'|'analyzing'|'done'>('idle');
  const [error, setError]                     = useState<string | null>(null);
  const [securityChecks, setSecurityChecks]   = useState<SecurityCheck[]>([]);
  const [detectedFormat, setDetectedFormat]   = useState<string>('');

  const pollRef       = useRef<ReturnType<typeof setInterval> | null>(null);
  const stageIdxRef   = useRef(1);
  // Cooldown – prevent rapid re-submissions
  const lastUploadRef = useRef<number>(0);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else setDragActive(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) validateAndSetFile(e.dataTransfer.files[0]);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) validateAndSetFile(e.target.files[0]);
  };

  // ── Client-side validation ───────────────────────────────────────────────
  const validateAndSetFile = async (selected: File) => {
    setError(null);
    setSecurityChecks([]);
    setDetectedFormat('');

    const checks: SecurityCheck[] = [];

    // 1. Filename sanitisation
    const basename   = selected.name.replace(/^.*[/\\]/, '');     // strip directory
    const clean      = basename.replace(/[\x00-\x1f<>:"|?*]/g, ''); // strip control chars
    const parts      = clean.split('.');
    const ext        = ('.' + parts[parts.length - 1]).toLowerCase();
    const innerExts  = new Set(parts.slice(1, -1).map(p => p.toLowerCase()));
    const hasDangerous = [...innerExts].some(x => DANGEROUS_INNER_EXTS.has(x));

    checks.push({
      label: 'Filename safety',
      status: (!hasDangerous && clean.length > 0 && clean.length <= 128) ? 'pass' : 'fail',
      detail: hasDangerous ? 'Multi-extension attack detected' : clean,
    });
    if (hasDangerous || clean.length === 0) {
      setError('Suspicious filename detected (possible multi-extension attack).');
      setSecurityChecks(checks);
      return;
    }

    // 2. Extension check
    checks.push({
      label: 'File extension',
      status: ALLOWED_EXTENSIONS.has(ext) ? 'pass' : 'fail',
      detail: ALLOWED_EXTENSIONS.has(ext) ? ext : `${ext} not allowed`,
    });
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      setError(`Extension '${ext}' is not allowed. Only .pcap, .pcapng, and .cap are accepted.`);
      setSecurityChecks(checks);
      return;
    }

    // 3. File size range
    const sizeOk = selected.size >= MIN_SIZE_BYTES && selected.size <= MAX_SIZE_BYTES;
    checks.push({
      label: 'File size',
      status: sizeOk ? 'pass' : 'fail',
      detail: sizeOk
        ? `${(selected.size / 1024).toFixed(1)} KB`
        : selected.size < MIN_SIZE_BYTES ? 'Too small' : 'Exceeds 50 MB limit',
    });
    if (!sizeOk) {
      setError(
        selected.size < MIN_SIZE_BYTES
          ? 'File is too small to be a valid capture.'
          : 'File exceeds the 50 MB maximum allowed size.'
      );
      setSecurityChecks(checks);
      return;
    }

    // 4. Magic bytes (client-side, from ArrayBuffer)
    try {
      const headerBytes = await readMagicBytes(selected, 24);
      const magic = matchesMagic(headerBytes);
      checks.push({
        label: 'Magic bytes',
        status: magic.ok ? 'pass' : 'fail',
        detail: magic.ok
          ? `${magic.label} (${Array.from(headerBytes.slice(0,4)).map(b=>b.toString(16).padStart(2,'0')).join(' ')})`
          : `Unknown header: ${Array.from(headerBytes.slice(0,4)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`,
      });
      if (!magic.ok) {
        setError('File signature does not match any known PCAP/PCAPNG format. The file may be corrupt or disguised.');
        setSecurityChecks(checks);
        return;
      }
      setDetectedFormat(magic.label ?? '');
    } catch {
      checks.push({ label: 'Magic bytes', status: 'fail', detail: 'Could not read file header' });
      setError('Could not read file. Please try again.');
      setSecurityChecks(checks);
      return;
    }

    setSecurityChecks(checks);
    setFile(selected);
  };

  // ── Polling ──────────────────────────────────────────────────────────────
  const pollStatus = (captureId: number) => {
    stageIdxRef.current = 1;
    setAnalysisProgress(5);
    setStage(ANALYSIS_STAGES[1]);

    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`${API_URL}/captures/${captureId}`);
        const data = await res.json();
        const status = data?.capture?.status;

        if (stageIdxRef.current < ANALYSIS_STAGES.length - 1) {
          stageIdxRef.current += 1;
          setStage(ANALYSIS_STAGES[stageIdxRef.current]);
          setAnalysisProgress(Math.min(90, stageIdxRef.current * 13));
        }

        if (status === 'completed') {
          clearInterval(pollRef.current!);
          setAnalysisProgress(100);
          setStage('Analysis complete!');
          setPhase('done');
          setTimeout(() => navigate('/analysis', { state: { captureId } }), 800);
        } else if (status === 'failed') {
          clearInterval(pollRef.current!);
          setUploading(false); setPhase('idle');
          setError('Backend analysis failed. Please try again.');
        }
      } catch { /* keep polling */ }
    }, 1500);
  };

  // ── Upload handler ────────────────────────────────────────────────────────
  const handleUpload = async () => {
    if (!file) return;

    // Client-side cooldown (10 s between uploads)
    const now = Date.now();
    if (now - lastUploadRef.current < 10_000) {
      setError('Please wait a moment before uploading again.');
      return;
    }
    lastUploadRef.current = now;

    setUploading(true); setError(null);
    setPhase('uploading'); setStage(ANALYSIS_STAGES[0]);

    try {
      const result = await uploadPcap(file, (ev) => {
        const pct = Math.round((ev.loaded * 100) / (ev.total || 1));
        setUploadProgress(pct);
        if (pct >= 100) setPhase('analyzing');
      });
      pollStatus(result.capture_id);
    } catch (err: any) {
      if (pollRef.current) clearInterval(pollRef.current);
      setUploading(false); setPhase('idle'); setUploadProgress(0);
      const detail = err.response?.data?.detail || 'An error occurred during upload or analysis.';
      setError(detail);
    }
  };

  const overallProgress =
    phase === 'uploading' ? Math.round(uploadProgress * 0.3)
    : phase === 'analyzing' ? 30 + Math.round(analysisProgress * 0.7)
    : phase === 'done' ? 100 : 0;

  const allChecksPassed = securityChecks.length > 0 && securityChecks.every(c => c.status === 'pass');

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Upload Capture</h1>
        <p className="text-slate-400 mt-1">
          Upload a PCAP file for deep packet analysis and threat detection. All files are validated before processing.
        </p>
      </div>

      {/* Security badge */}
      <div className="flex items-center space-x-2 text-xs font-mono text-slate-500 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2 w-fit">
        <Lock size={12} className="text-accent" />
        <span>Extension · Magic-byte · Size · Path-traversal · Rate-limit · SHA-256 dedup</span>
      </div>

      {/* Error banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            className="bg-rose-500/10 border border-rose-500/50 text-rose-400 p-4 rounded-xl flex items-start space-x-3"
          >
            <ShieldAlert className="mt-0.5 shrink-0" size={20} />
            <p className="font-mono text-sm">{error}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Security check results */}
      <AnimatePresence>
        {securityChecks.length > 0 && !uploading && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className={`border rounded-xl p-4 space-y-2 ${allChecksPassed ? 'border-accent/30 bg-accent/5' : 'border-rose-500/30 bg-rose-500/5'}`}
          >
            <div className="flex items-center space-x-2 mb-3">
              {allChecksPassed
                ? <ShieldCheck size={16} className="text-accent" />
                : <ShieldAlert size={16} className="text-rose-400" />}
              <span className="text-xs font-mono uppercase tracking-widest text-slate-300">
                {allChecksPassed ? 'All security checks passed' : 'Security validation failed'}
              </span>
            </div>
            {securityChecks.map((chk, i) => (
              <div key={i} className="flex items-center justify-between text-xs font-mono">
                <div className="flex items-center space-x-2">
                  <span className={chk.status === 'pass' ? 'text-accent' : 'text-rose-400'}>
                    {chk.status === 'pass' ? '✓' : '✗'}
                  </span>
                  <span className="text-slate-400 uppercase tracking-wider">{chk.label}</span>
                </div>
                <span className={`${chk.status === 'pass' ? 'text-slate-400' : 'text-rose-400'} max-w-xs truncate text-right`}>
                  {chk.detail}
                </span>
              </div>
            ))}
            {detectedFormat && allChecksPassed && (
              <p className="text-xs font-mono text-accent/70 pt-1 border-t border-accent/10">
                Detected format: {detectedFormat}
              </p>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Drop zone */}
      <motion.div
        initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
        className={`relative border border-dashed rounded-3xl p-12 transition-all duration-300 flex flex-col items-center justify-center min-h-[400px]
          ${dragActive ? 'border-accent bg-accent/5 shadow-[0_0_30px_rgba(34,197,94,0.1)]' : 'border-dark-700 bg-dark-800 hover:border-accent/50'}
          ${uploading ? 'pointer-events-none' : ''}
        `}
        onDragEnter={handleDrag} onDragLeave={handleDrag} onDragOver={handleDrag} onDrop={handleDrop}
      >
        <input type="file" id="file-upload" className="hidden" onChange={handleChange} accept=".pcap,.pcapng,.cap" />

        {/* ── Idle: no file ── */}
        {!file && !uploading && (
          <>
            <div className="bg-dark-900 p-6 rounded-full shadow-lg mb-6 text-accent border border-accent/20">
              <UploadCloud size={48} />
            </div>
            <h3 className="text-2xl font-mono text-white mb-2 uppercase tracking-wide">Drag & drop your PCAP here</h3>
            <p className="text-slate-400 mb-2 font-mono text-sm">Supports .pcap, .pcapng, .cap — max 50 MB</p>
            <p className="text-slate-600 mb-8 font-mono text-xs">Files are validated client-side and server-side before processing</p>
            <label
              htmlFor="file-upload"
              className="bg-accent/10 hover:bg-accent/20 text-accent border border-accent/50 px-8 py-3 rounded-xl font-mono uppercase tracking-wider cursor-pointer transition-all shadow-[0_0_15px_rgba(34,197,94,0.15)] hover:shadow-[0_0_25px_rgba(34,197,94,0.3)]"
            >Browse Files</label>
          </>
        )}

        {/* ── File selected, not uploading ── */}
        {file && !uploading && (
          <div className="w-full max-w-md">
            <div className="bg-dark-900 border border-dark-700 rounded-2xl p-6 flex items-center space-x-4">
              <div className={`p-3 rounded-lg ${allChecksPassed ? 'bg-accent/10 text-accent' : 'bg-rose-500/10 text-rose-400'}`}>
                <File size={32} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-white font-medium truncate">{file.name}</p>
                <p className="text-slate-400 text-sm">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                {detectedFormat && <p className="text-accent text-xs font-mono mt-0.5">{detectedFormat}</p>}
              </div>
              <button onClick={() => { setFile(null); setSecurityChecks([]); setDetectedFormat(''); }} className="text-slate-500 hover:text-rose-400 transition-colors p-2">
                <AlertCircle size={20} />
              </button>
            </div>

            {allChecksPassed && (
              <div className="mt-8 flex justify-end space-x-4">
                <button onClick={() => { setFile(null); setSecurityChecks([]); setDetectedFormat(''); }} className="px-6 py-2.5 rounded-xl text-slate-300 hover:bg-dark-700 font-mono transition-colors uppercase text-sm">
                  Cancel
                </button>
                <button
                  onClick={handleUpload}
                  className="px-6 py-2.5 bg-accent/10 hover:bg-accent/20 border border-accent/50 text-accent rounded-xl font-mono uppercase tracking-wider shadow-[0_0_15px_rgba(34,197,94,0.15)] transition-all flex items-center space-x-2 text-sm"
                >
                  <UploadCloud size={18} />
                  <span>Analyze Capture</span>
                </button>
              </div>
            )}

            {!allChecksPassed && (
              <p className="text-center text-rose-400 font-mono text-xs mt-6">
                ✗ File rejected by security checks. Please upload a valid PCAP file.
              </p>
            )}
          </div>
        )}

        {/* ── Uploading / Analyzing ── */}
        {uploading && (
          <div className="w-full max-w-lg space-y-8">
            <div className="flex justify-center">
              {phase === 'done'
                ? <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="p-5 bg-accent/10 rounded-full border border-accent/30">
                    <CheckCircle2 size={48} className="text-accent drop-shadow-[0_0_12px_rgba(34,197,94,0.8)]" />
                  </motion.div>
                : <div className="relative p-5 bg-dark-900 rounded-full border border-accent/20">
                    <Loader2 size={48} className="text-accent animate-spin" />
                    <div className="absolute inset-0 rounded-full bg-accent/5 animate-ping" />
                  </div>
              }
            </div>

            <div className="text-center space-y-1">
              <AnimatePresence mode="wait">
                <motion.p key={stage} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.25 }}
                  className="text-white font-mono uppercase tracking-widest text-sm">{stage}</motion.p>
              </AnimatePresence>
              <p className="text-slate-500 font-mono text-xs">{file?.name}</p>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono text-slate-400">
                <span className="uppercase tracking-wider">
                  {phase === 'uploading' ? 'Uploading' : phase === 'analyzing' ? 'Analyzing' : 'Complete'}
                </span>
                <span className="text-accent">{overallProgress}%</span>
              </div>
              <div className="h-2 bg-dark-900 rounded-full overflow-hidden border border-dark-700">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: 'linear-gradient(90deg, #16a34a, #22c55e, #4ade80)' }}
                  animate={{ width: `${overallProgress}%` }}
                  transition={{ duration: 0.4, ease: 'easeOut' }}
                />
              </div>
            </div>

            <div className="flex justify-center space-x-2">
              {ANALYSIS_STAGES.slice(1).map((_, i) => (
                <div key={i} className={`w-1.5 h-1.5 rounded-full transition-all duration-300 ${i < stageIdxRef.current ? 'bg-accent' : 'bg-dark-600'}`} />
              ))}
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default Upload;
