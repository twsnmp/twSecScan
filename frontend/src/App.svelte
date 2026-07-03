<script>
  import { onMount } from 'svelte';

  // Svelte 5 Runes for state management
  let activeTab = $state('dashboard'); // 'dashboard', 'history', 'settings'
  let target = $state('');
  let scanning = $state(false);
  let scanHistory = $state([]);
  let selectedScan = $state(null);
  let findings = $state([]);
  let settings = $state({
    api_key_openai: '',
    api_key_anthropic: '',
    ollama_url: 'http://localhost:11434',
    ollama_model: 'llama3',
    active_provider: 'ollama',
    scan_concurrency: 10
  });
  let toastMsg = $state('');
  let searchHistoryQuery = $state('');
  let showDeleteConfirm = $state(false);
  let scanToDelete = $state(null);

  // Derived state
  let filteredHistory = $derived(
    scanHistory.filter(s => 
      s.target.toLowerCase().includes(searchHistoryQuery.toLowerCase()) ||
      s.status.toLowerCase().includes(searchHistoryQuery.toLowerCase())
    )
  );

  // Helper for safe Wails binding calls
  async function callBind(method, ...args) {
    if (window.go && window.go.main && window.go.main.App && window.go.main.App[method]) {
      return await window.go.main.App[method](...args);
    }
    // Mock fallbacks for standalone browser previews
    console.warn(`Wails method ${method} not found, using mockup data.`);
    if (method === 'GetConfig') {
      return { ...settings };
    }
    if (method === 'ListScans') {
      return [
        {
          id: 'mock_1',
          target: 'example.com',
          status: 'completed',
          start_time: new Date(Date.now() - 3600000).toISOString(),
          end_time: new Date(Date.now() - 3500000).toISOString(),
          finding_count: { high: 1, medium: 2, low: 4 }
        },
        {
          id: 'mock_2',
          target: '127.0.0.1',
          status: 'failed',
          start_time: new Date(Date.now() - 7200000).toISOString(),
          end_time: new Date(Date.now() - 7180000).toISOString(),
          error_msg: 'failed to resolve host'
        }
      ];
    }
    if (method === 'GetFindings') {
      return [
        {
          id: 'find_80',
          scan_id: args[0],
          target: 'example.com',
          module: 'osint',
          title: 'Open Port Detected: 80',
          description: 'TCP Port 80 is open. It serves unencrypted HTTP traffic.',
          severity: 'medium',
          proof: 'Successfully established TCP connection.',
          ai_advice: 'Enforce HTTPS redirect and close port 80 if unnecessary, routing all traffic through port 443 with TLS.',
          timestamp: new Date().toISOString()
        },
        {
          id: 'find_23',
          scan_id: args[0],
          target: 'example.com',
          module: 'osint',
          title: 'Open Port Detected: 23',
          description: 'TCP Port 23 is open. Telnet sends authentication in plaintext.',
          severity: 'high',
          proof: 'Telnet banner detected: mock-telnet-d.',
          ai_advice: 'Immediately disable Telnet service. Replace with SSH (port 22) for secure, encrypted remote access.',
          timestamp: new Date().toISOString()
        }
      ];
    }
    if (method === 'StartScan') {
      return {
        id: 'mock_' + Date.now(),
        target: args[0],
        status: 'running',
        start_time: new Date().toISOString(),
        finding_count: {}
      };
    }
    return null;
  }

  function showToast(msg) {
    toastMsg = msg;
    setTimeout(() => {
      toastMsg = '';
    }, 3000);
  }

  async function loadConfig() {
    try {
      const cfg = await callBind('GetConfig');
      if (cfg) {
        settings = {
          api_key_openai: cfg.api_key_openai || '',
          api_key_anthropic: cfg.api_key_anthropic || '',
          ollama_url: cfg.ollama_url || 'http://localhost:11434',
          ollama_model: cfg.ollama_model || 'llama3',
          active_provider: cfg.active_provider || 'ollama',
          scan_concurrency: cfg.scan_concurrency || 10
        };
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function saveConfig() {
    try {
      await callBind('SaveConfig', {
        api_key_openai: settings.api_key_openai,
        api_key_anthropic: settings.api_key_anthropic,
        ollama_url: settings.ollama_url,
        ollama_model: settings.ollama_model,
        active_provider: settings.active_provider,
        scan_concurrency: Number(settings.scan_concurrency)
      });
      showToast('Settings saved successfully!');
    } catch (e) {
      showToast('Failed to save settings: ' + e.message);
    }
  }

  async function loadHistory() {
    try {
      const history = await callBind('ListScans');
      if (history) {
        scanHistory = history;
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function triggerScan() {
    if (!target) {
      showToast('Please enter a target IP or domain.');
      return;
    }
    scanning = true;
    showToast(`Scan initiated for ${target}...`);
    try {
      const scan = await callBind('StartScan', target);
      if (scan) {
        await loadHistory();
        // Periodically poll for updates until the active scan completes
        pollActiveScan(scan.id);
      }
    } catch (e) {
      scanning = false;
      showToast('Scan failed: ' + e.message);
    }
  }

  async function pollActiveScan(scanID) {
    const timer = setInterval(async () => {
      try {
        const history = await callBind('ListScans');
        if (history) {
          scanHistory = history;
          const current = history.find(s => s.id === scanID);
          if (current && current.status !== 'running') {
            clearInterval(timer);
            scanning = false;
            showToast(`Scan for ${current.target} finished with status: ${current.status}`);
            viewDetails(current);
          }
        }
      } catch (e) {
        clearInterval(timer);
        scanning = false;
      }
    }, 2000);
  }

  async function viewDetails(scan) {
    selectedScan = scan;
    try {
      const result = await callBind('GetFindings', scan.id);
      findings = result || [];
    } catch (e) {
      findings = [];
    }
    activeTab = 'history';
  }

  function confirmDeleteScan(scanID) {
    scanToDelete = scanID;
    showDeleteConfirm = true;
  }

  async function executeDeleteScan() {
    if (!scanToDelete) return;
    try {
      await callBind('DeleteScan', scanToDelete);
      showToast('Scan history deleted.');
      if (selectedScan && selectedScan.id === scanToDelete) {
        selectedScan = null;
        findings = [];
      }
      await loadHistory();
    } catch (e) {
      showToast('Delete failed: ' + e.message);
    } finally {
      showDeleteConfirm = false;
      scanToDelete = null;
    }
  }

  onMount(() => {
    loadConfig();
    loadHistory();
  });
</script>

<div class="min-h-screen flex text-slate-100 font-sans">
  <!-- Sidebar -->
  <aside class="w-64 glass-panel border-r border-slate-700/50 flex flex-col justify-between">
    <div>
      <!-- Brand Logo -->
      <div class="p-6 border-b border-slate-700/50">
        <h1 class="text-xl font-bold tracking-wider bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
          twSecScan
        </h1>
        <p class="text-xs text-slate-400 mt-1">AI-Powered Security Suite</p>
      </div>

      <!-- Navigation Menu -->
      <nav class="p-4 space-y-2">
        <button
          onclick={() => activeTab = 'dashboard'}
          class="w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all {activeTab === 'dashboard' ? 'bg-indigo-600/80 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-400 hover:bg-slate-800/50 hover:text-white'}"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
          Dashboard
        </button>

        <button
          onclick={() => activeTab = 'history'}
          class="w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all {activeTab === 'history' ? 'bg-indigo-600/80 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-400 hover:bg-slate-800/50 hover:text-white'}"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          Scan History
        </button>

        <button
          onclick={() => activeTab = 'settings'}
          class="w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-all {activeTab === 'settings' ? 'bg-indigo-600/80 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-400 hover:bg-slate-800/50 hover:text-white'}"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
          Settings
        </button>
      </nav>
    </div>

    <div class="p-4 border-t border-slate-700/50 text-xs text-slate-500 text-center">
      v0.1.0 • Pure Go Engine
    </div>
  </aside>

  <!-- Main Content Area -->
  <main class="flex-1 flex flex-col overflow-hidden">
    <!-- Header -->
    <header class="h-16 border-b border-slate-700/50 flex items-center justify-between px-8 bg-slate-900/30 backdrop-blur">
      <h2 class="text-lg font-semibold text-slate-200 capitalize">{activeTab}</h2>
      <div class="flex items-center gap-3">
        {#if scanning}
          <div class="flex items-center gap-2 text-indigo-400 text-sm">
            <span class="animate-pulse w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
            Scan in progress...
          </div>
        {/if}
      </div>
    </header>

    <!-- Views -->
    <div class="flex-1 overflow-y-auto p-8">
      {#if activeTab === 'dashboard'}
        <!-- Dashboard / Single Click Scan Entry -->
        <div class="max-w-3xl mx-auto space-y-8 mt-4">
          <div class="text-center space-y-3">
            <h3 class="text-3xl font-extrabold tracking-tight text-white">Target Vulnerability Scanning</h3>
            <p class="text-slate-400 text-sm max-w-md mx-auto">
              Scan target ports & use local/cloud AI analysis to formulate real-time, actionable security advise.
            </p>
          </div>

          <!-- Glass Scan Panel -->
          <div class="glass-panel p-6 rounded-2xl shadow-xl space-y-4">
            <div class="flex gap-4">
              <input
                type="text"
                bind:value={target}
                disabled={scanning}
                placeholder="example.com or 192.168.1.1"
                class="flex-1 px-4 py-3 rounded-xl glass-input text-base"
              />
              <button
                onclick={triggerScan}
                disabled={scanning}
                class="px-8 py-3 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 text-white font-medium shadow-md shadow-indigo-500/20 transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {#if scanning}
                  <svg class="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  Scanning...
                {:else}
                  Start Scan
                {/if}
              </button>
            </div>
            
            <div class="text-xs text-slate-500 flex items-center gap-2">
              <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
              Scans standard TCP ports (SSH, HTTP, Database etc.) and executes AI recommendation queries.
            </div>
          </div>

          <!-- Quick Stats / Recent Activity Summary -->
          <div class="grid grid-cols-3 gap-6">
            <div class="glass-card p-6 rounded-2xl flex flex-col justify-between">
              <span class="text-xs text-slate-400 uppercase font-medium tracking-wider">Total Scans Run</span>
              <span class="text-3xl font-bold mt-2 text-white">{scanHistory.length}</span>
            </div>
            <div class="glass-card p-6 rounded-2xl flex flex-col justify-between">
              <span class="text-xs text-slate-400 uppercase font-medium tracking-wider">Active Provider</span>
              <span class="text-2xl font-bold mt-2 text-indigo-400 capitalize">{settings.active_provider}</span>
            </div>
            <div class="glass-card p-6 rounded-2xl flex flex-col justify-between">
              <span class="text-xs text-slate-400 uppercase font-medium tracking-wider">Max Concurrency</span>
              <span class="text-3xl font-bold mt-2 text-purple-400">{settings.scan_concurrency}</span>
            </div>
          </div>
        </div>

      {:else if activeTab === 'history'}
        <!-- Scan History & Findings Details -->
        <div class="grid grid-cols-12 gap-8 h-full">
          <!-- History List Left -->
          <div class="col-span-5 space-y-4">
            <div class="flex items-center gap-2">
              <input
                type="text"
                bind:value={searchHistoryQuery}
                placeholder="Search history..."
                class="w-full px-3 py-2 rounded-lg glass-input text-sm"
              />
            </div>

            <div class="space-y-3 overflow-y-auto max-h-[500px] pr-2">
              {#if filteredHistory.length === 0}
                <div class="text-slate-500 text-sm text-center py-8">No scans recorded yet.</div>
              {/if}
              {#each filteredHistory as scan}
                <div
                  role="button"
                  tabindex="0"
                  onclick={() => viewDetails(scan)}
                  onkeydown={(e) => e.key === 'Enter' && viewDetails(scan)}
                  class="w-full text-left p-4 rounded-xl glass-card transition-all flex justify-between items-center hover:bg-slate-800/40 border {selectedScan?.id === scan.id ? 'border-indigo-500/50 bg-indigo-950/20' : 'border-transparent'} cursor-pointer"
                >
                  <div class="space-y-1">
                    <div class="font-semibold text-white truncate max-w-[200px]">{scan.target}</div>
                    <div class="text-xs text-slate-400">
                      {new Date(scan.start_time).toLocaleString()}
                    </div>
                    <div class="flex gap-2 mt-1">
                      {#if scan.finding_count && Object.keys(scan.finding_count).length > 0}
                        {#each Object.entries(scan.finding_count) as [sev, count]}
                          {#if count > 0}
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full capitalize font-semibold 
                              {sev === 'critical' ? 'bg-red-950/50 text-red-400 border border-red-500/20' : ''}
                              {sev === 'high' ? 'bg-orange-950/50 text-orange-400 border border-orange-500/20' : ''}
                              {sev === 'medium' ? 'bg-yellow-950/50 text-yellow-400 border border-yellow-500/20' : ''}
                              {sev === 'low' ? 'bg-blue-950/50 text-blue-400 border border-blue-500/20' : ''}
                              {sev === 'info' ? 'bg-slate-800 text-slate-300' : ''}
                            ">
                              {sev}: {count}
                            </span>
                          {/if}
                        {/each}
                      {:else if scan.status === 'completed'}
                        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-950/50 text-emerald-400 border border-emerald-500/20">Clean</span>
                      {/if}
                    </div>
                  </div>

                  <div class="flex flex-col items-end gap-2">
                    <span class="text-xs px-2.5 py-0.5 rounded-full capitalize font-medium
                      {scan.status === 'completed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/20' : ''}
                      {scan.status === 'failed' ? 'bg-red-950 text-red-400 border border-red-500/20' : ''}
                      {scan.status === 'running' ? 'bg-indigo-950 text-indigo-400 border border-indigo-500/20 animate-pulse' : ''}
                    ">
                      {scan.status}
                    </span>
                    <button
                      onclick={(e) => { e.stopPropagation(); confirmDeleteScan(scan.id); }}
                      class="text-slate-500 hover:text-red-400 p-1 transition-colors"
                      title="Delete scan"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                    </button>
                  </div>
                </div>
              {/each}
            </div>
          </div>

          <!-- Findings List Right -->
          <div class="col-span-7 space-y-4">
            {#if !selectedScan}
              <div class="glass-panel rounded-2xl p-8 text-center text-slate-500 h-full flex flex-col justify-center items-center">
                <svg class="w-12 h-12 text-slate-600 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                Select a scan from history to view detailed findings and AI advice.
              </div>
            {:else}
              <div class="glass-panel rounded-2xl p-6 space-y-6 max-h-[600px] overflow-y-auto">
                <div class="flex justify-between items-start border-b border-slate-700/50 pb-4">
                  <div>
                    <h3 class="text-xl font-bold text-white truncate max-w-[400px]">{selectedScan.target}</h3>
                    <p class="text-xs text-slate-400 mt-1">
                      Run ID: {selectedScan.id} • Started: {new Date(selectedScan.start_time).toLocaleString()}
                    </p>
                  </div>
                  {#if selectedScan.error_msg}
                    <div class="text-xs text-red-400 bg-red-950/30 p-2 rounded-lg border border-red-500/20 max-w-xs">
                      Error: {selectedScan.error_msg}
                    </div>
                  {/if}
                </div>

                <div class="space-y-4">
                  <h4 class="text-sm font-semibold text-slate-300 uppercase tracking-wider">Vulnerabilities / Findings ({findings.length})</h4>
                  
                  {#if findings.length === 0}
                    <div class="text-slate-500 text-sm py-4">No security vulnerabilities identified.</div>
                  {/if}

                  {#each findings as finding}
                    <div class="glass-card rounded-xl p-5 border-l-4 
                      {finding.severity === 'critical' ? 'border-red-500 bg-red-950/5' : ''}
                      {finding.severity === 'high' ? 'border-orange-500 bg-orange-950/5' : ''}
                      {finding.severity === 'medium' ? 'border-yellow-500 bg-yellow-950/5' : ''}
                      {finding.severity === 'low' ? 'border-blue-500 bg-blue-950/5' : ''}
                      {finding.severity === 'info' ? 'border-slate-500 bg-slate-800/10' : ''}
                    ">
                      <div class="flex justify-between items-start gap-4">
                        <h5 class="font-bold text-slate-200">{finding.title}</h5>
                        <span class="text-[10px] px-2 py-0.5 rounded-full capitalize font-bold tracking-wide
                          {finding.severity === 'critical' ? 'bg-red-500/20 text-red-300' : ''}
                          {finding.severity === 'high' ? 'bg-orange-500/20 text-orange-300' : ''}
                          {finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' : ''}
                          {finding.severity === 'low' ? 'bg-blue-500/20 text-blue-300' : ''}
                          {finding.severity === 'info' ? 'bg-slate-500/20 text-slate-300' : ''}
                        ">
                          {finding.severity}
                        </span>
                      </div>

                      <p class="text-sm text-slate-400 mt-2">{finding.description}</p>
                      
                      {#if finding.proof}
                        <div class="mt-3 bg-slate-950/40 p-2.5 rounded text-xs font-mono text-slate-300 border border-slate-800/80">
                          <strong>Proof:</strong> {finding.proof}
                        </div>
                      {/if}

                      {#if finding.ai_advice}
                        <div class="mt-3 bg-indigo-950/20 p-3 rounded-lg border border-indigo-500/10 text-xs space-y-1">
                          <div class="text-indigo-400 font-semibold flex items-center gap-1.5">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                            AI Mitigation Strategy:
                          </div>
                          <p class="text-slate-300 leading-relaxed whitespace-pre-line">{finding.ai_advice}</p>
                        </div>
                      {/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
          </div>
        </div>

      {:else if activeTab === 'settings'}
        <!-- Settings Form -->
        <div class="max-w-2xl mx-auto glass-panel p-8 rounded-2xl shadow-xl space-y-6">
          <div class="border-b border-slate-700/50 pb-4">
            <h3 class="text-xl font-bold text-white">Application Configuration</h3>
            <p class="text-xs text-slate-400 mt-1">Setup scanning constraints and AI provider authentication keys.</p>
          </div>

          <div class="space-y-4">
            <div class="grid grid-cols-2 gap-4">
              <!-- Active LLM Provider -->
              <div class="flex flex-col gap-2">
                <label for="provider" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active AI Provider</label>
                <select
                  id="provider"
                  bind:value={settings.active_provider}
                  class="px-3 py-2 rounded-lg glass-input text-sm"
                >
                  <option value="ollama">Ollama (Local)</option>
                  <option value="openai">OpenAI (Cloud)</option>
                  <option value="anthropic">Anthropic (Cloud)</option>
                </select>
              </div>

              <!-- Concurrency -->
              <div class="flex flex-col gap-2">
                <label for="concurrency" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scan Concurrency</label>
                <input
                  id="concurrency"
                  type="number"
                  bind:value={settings.scan_concurrency}
                  class="px-3 py-2 rounded-lg glass-input text-sm"
                />
              </div>
            </div>

            {#if settings.active_provider === 'ollama'}
              <!-- Ollama Options -->
              <div class="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
                <div class="flex flex-col gap-2">
                  <label for="ollamaUrl" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Ollama Endpoint URL</label>
                  <input
                    id="ollamaUrl"
                    type="text"
                    bind:value={settings.ollama_url}
                    class="px-3 py-2 rounded-lg glass-input text-sm"
                  />
                </div>
                <div class="flex flex-col gap-2">
                  <label for="ollamaModel" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Ollama Model</label>
                  <input
                    id="ollamaModel"
                    type="text"
                    bind:value={settings.ollama_model}
                    class="px-3 py-2 rounded-lg glass-input text-sm"
                  />
                </div>
              </div>
            {:else}
              <!-- API Keys -->
              <div class="flex flex-col gap-2 border-t border-slate-800 pt-4">
                {#if settings.active_provider === 'openai'}
                  <label for="openaiKey" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">OpenAI API Key</label>
                  <input
                    id="openaiKey"
                    type="password"
                    bind:value={settings.api_key_openai}
                    placeholder="sk-..."
                    class="px-3 py-2 rounded-lg glass-input text-sm"
                  />
                {:else if settings.active_provider === 'anthropic'}
                  <label for="anthropicKey" class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Anthropic API Key</label>
                  <input
                    id="anthropicKey"
                    type="password"
                    bind:value={settings.api_key_anthropic}
                    placeholder="sk-ant-..."
                    class="px-3 py-2 rounded-lg glass-input text-sm"
                  />
                {/if}
              </div>
            {/if}
          </div>

          <div class="border-t border-slate-700/50 pt-6 flex justify-end">
            <button
              onclick={saveConfig}
              class="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-medium shadow-md shadow-indigo-600/10 transition-colors"
            >
              Save Configuration
            </button>
          </div>
        </div>
      {/if}
    </div>
    </main>
  </div>

<!-- Custom Delete Confirmation Modal -->
{#if showDeleteConfirm}
  <div class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex justify-center items-center z-50 transition-opacity duration-300">
    <div class="glass-panel max-w-md w-full mx-4 rounded-2xl border border-red-500/20 shadow-2xl p-6 space-y-6 transform transition-all">
      <div class="flex items-start gap-4">
        <div class="p-3 bg-red-950/50 rounded-full border border-red-500/20 text-red-400 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        </div>
        <div class="space-y-1">
          <h3 class="text-lg font-semibold text-white">Delete Scan History</h3>
          <p class="text-sm text-slate-400">Are you sure you want to delete this scan history? This action cannot be undone.</p>
        </div>
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button
          onclick={() => { showDeleteConfirm = false; scanToDelete = null; }}
          class="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 transition-colors text-sm font-medium"
        >
          Cancel
        </button>
        <button
          onclick={executeDeleteScan}
          class="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white shadow-lg shadow-red-600/20 transition-colors text-sm font-medium"
        >
          Delete
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Toast message -->
{#if toastMsg}
  <div class="fixed bottom-6 right-6 px-5 py-3 rounded-xl bg-slate-900 border border-indigo-500/30 text-white text-sm shadow-2xl z-50 flex items-center gap-2 animate-bounce">
    <span class="w-2 h-2 bg-indigo-500 rounded-full animate-ping"></span>
    {toastMsg}
  </div>
{/if}
