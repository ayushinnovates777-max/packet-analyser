import { Save } from 'lucide-react';

const Settings = () => {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Settings</h1>
        <p className="text-slate-400 mt-1">Configure analysis engine and system preferences.</p>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-2xl overflow-hidden shadow-lg">
        <div className="p-6 border-b border-dark-700">
          <h2 className="text-lg font-semibold text-white">Detection Engine</h2>
          <p className="text-sm text-slate-400 mt-1">Manage heuristic rules and detection thresholds.</p>
        </div>
        <div className="p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium text-white">Heuristic Analysis</p>
              <p className="text-sm text-slate-400">Enable rule-based threat detection</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" value="" className="sr-only peer" defaultChecked />
              <div className="w-11 h-6 bg-dark-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
            </label>
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium text-white">Port Scan Threshold</p>
              <p className="text-sm text-slate-400">SYN packets before alert</p>
            </div>
            <input type="number" defaultValue={50} className="bg-dark-900 border border-dark-700 text-white text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block w-24 p-2.5" />
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button className="px-6 py-2.5 bg-primary-500 hover:bg-primary-600 text-white rounded-xl font-medium shadow-lg shadow-primary-500/20 transition-colors flex items-center space-x-2">
          <Save size={18} />
          <span>Save Changes</span>
        </button>
      </div>
    </div>
  );
};

export default Settings;
