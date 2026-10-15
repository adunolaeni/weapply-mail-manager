import { useState, useEffect, FormEvent } from "react";
import { Plus, Trash2, KeyRound, Globe, Wifi, AlertTriangle, Layers, Calendar, ChevronRight, Check, Mail } from "lucide-react";
import { Client } from "../types";

interface ClientManagerProps {
  clients: Client[];
  loading: boolean;
  onRefresh: () => void;
  token: string;
}

export default function ClientManager({ clients, loading, onRefresh, token }: ClientManagerProps) {
  const [showImapForm, setShowImapForm] = useState(false);
  const [imapProvider, setImapProvider] = useState<"generic" | "yahoo">("generic");
  const [clientName, setClientName] = useState("");
  const [email, setEmail] = useState("");
  const [imapHost, setImapHost] = useState("");
  const [imapPort, setImapPort] = useState("993");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [microsoftLoading, setMicrosoftLoading] = useState(false);

  // ✅ Auto-fill IMAP settings based on provider selection
  useEffect(() => {
    if (imapProvider === "yahoo") {
      setImapHost("imap.mail.yahoo.com");
      setImapPort("993");
    } else {
      setImapHost("");
      setImapPort("993");
    }
  }, [imapProvider]);

  const handleOAuthConnect = async () => {
    setOauthLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/clients/oauth-link", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to retrieve OAuth authorization URL.");
      
      window.location.href = data.url;
    } catch (err: any) {
      setError(err?.message || "OAuth redirection failure.");
      setOauthLoading(false);
    }
  };

  const handleMicrosoftConnect = async () => {
    setMicrosoftLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/clients/microsoft/oauth-link", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Microsoft connection could not be started.");
      window.location.href = data.url;
    } catch (err: any) {
      setError(err?.message || "Microsoft connection failed.");
      setMicrosoftLoading(false);
    }
  };

  const handleImapSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!clientName || !email || !imapHost || !password) {
      setError("Please fill in all requested IMAP credentials.");
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      const res = await fetch("/api/clients/imap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          client_name: clientName,
          email,
          imap_host: imapHost,
          imap_port: parseInt(imapPort, 10),
          password,
          provider: imapProvider === "generic" ? "other" : imapProvider,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "IMAP client connection rejected.");

      setClientName("");
      setEmail("");
      setImapHost("");
      setImapPort("993");
      setPassword("");
      setShowImapForm(false);
      setImapProvider("generic");
      onRefresh();
    } catch (err: any) {
      setError(err?.message || "Server rejected registration.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteClient = async (id: number) => {
    if (!window.confirm("Are you sure you want to stop syncing this inbox? All associated emails will be permanently removed.")) {
      return;
    }

    setError(null);
    try {
      const res = await fetch(`/api/clients/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to delete client mailbox.");

      onRefresh();
    } catch (err: any) {
      setError(err?.message || "Removal unsuccessful.");
    }
  };  return (
    <div className="space-y-6 bg-slate-100 dark:bg-slate-950 min-h-screen p-8 animate-fadeIn">
      {/* Overview stats & actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-white dark:bg-slate-900/40 backdrop-blur-md p-5 rounded-2xl border border-slate-200/60 dark:border-slate-700/50 shadow-xs">
        <div>
          <h2 className="text-sm font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2">
            <Layers className="h-4.5 w-4.5 text-indigo-650 dark:text-indigo-400" />
            <span>Target Mailbox Connections</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-405 mt-0.5">Linked Gmail and Microsoft mailboxes (OAuth 2.0), Yahoo, and corporate IMAP sources</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Gmail OAuth button */}
          <button
            id="oauth-connect-btn"
            disabled={oauthLoading}
            onClick={handleOAuthConnect}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg bg-indigo-650 hover:bg-indigo-600 text-white transition-all cursor-pointer disabled:opacity-50 shadow-sm shadow-indigo-600/10 active:scale-95"
          >
            <Globe className="h-3.5 w-3.5" />
            <span>{oauthLoading ? "Redirecting..." : "Connect Google API"}</span>
          </button>

          {/* Microsoft read-only Mail API; no passwords needed. */}
          <button
            id="microsoft-oauth-connect-btn"
            disabled={microsoftLoading}
            onClick={handleMicrosoftConnect}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-all cursor-pointer disabled:opacity-50 shadow-sm active:scale-95"
          >
            <Mail className="h-3.5 w-3.5" />
            <span>{microsoftLoading ? "Redirecting..." : "Connect Hotmail / Outlook"}</span>
          </button>

          {/* IMAP toggle button */}
          <button
            id="imap-form-toggle-btn"
            onClick={() => setShowImapForm(!showImapForm)}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700/80 border border-slate-200 dark:border-slate-700 text-slate-705 dark:text-slate-205 transition-all cursor-pointer active:scale-95"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Connect IMAP Fallback</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-start space-x-2.5 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/25 text-rose-700 dark:text-rose-400 text-xs font-semibold border border-rose-150 dark:border-rose-900/50 italic animate-fadeIn">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>Error details: {error}</span>
        </div>
      )}

      {/* Manual IMAP Setup Panel Form */}
      {showImapForm && (
        <form onSubmit={handleImapSubmit} className="bg-white dark:bg-slate-900/40 backdrop-blur-md p-6 rounded-2xl border border-slate-200/60 dark:border-slate-700/50 space-y-4 animate-fadeIn shadow-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider flex items-center space-x-1.5 font-mono">
              <KeyRound className="h-4 w-4 text-indigo-650 dark:text-indigo-400" />
              <span>Link New Fallback IMAP Mailbox</span>
            </h3>
            <button 
              type="button" 
              onClick={() => setShowImapForm(false)} 
              className="text-xs font-bold text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-455 transition-colors cursor-pointer"
            >
              Cancel Form
            </button>
          </div>

          {/* ✅ Provider Selection */}
          <div className="space-y-2">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">Email Provider</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setImapProvider("yahoo")}
                className={`px-3 py-2 text-xs font-bold rounded-lg border transition-all cursor-pointer flex items-center justify-center gap-1.5 active:scale-98 ${
                  imapProvider === "yahoo" 
                    ? "bg-purple-50 border-purple-200 text-purple-700 dark:bg-purple-950/20 dark:border-purple-900/40 dark:text-purple-400" 
                    : "bg-slate-50 border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700/60"
                }`}
              >
                <Mail className="h-3.5 w-3.5" />
                Yahoo Mail
              </button>
              <button
                type="button"
                onClick={() => setImapProvider("generic")}
                className={`px-3 py-2 text-xs font-bold rounded-lg border transition-all cursor-pointer active:scale-98 ${
                  imapProvider === "generic" 
                    ? "bg-slate-100 border-slate-300 text-slate-900 dark:bg-slate-800/80 dark:border-slate-700 dark:text-slate-100" 
                    : "bg-slate-50 border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700/60"
                }`}
              >
                Other/Corporate
              </button>
            </div>
          </div>

          {/* ✅ Yahoo App Password Help */}
          {imapProvider === "yahoo" && (
            <div className="bg-purple-50 dark:bg-purple-950/15 border border-purple-100 dark:border-purple-900/40 rounded-xl p-4 space-y-2">
              <p className="text-xs font-bold text-purple-800 dark:text-purple-400 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 text-purple-650" />
                Yahoo App Password Required
              </p>
              <p className="text-[11px] text-purple-700 dark:text-purple-300">
                Yahoo requires a special App Password for third-party apps. Your regular password won't work.
              </p>
              <ol className="text-[11px] text-purple-700 dark:text-purple-300 list-decimal list-inside space-y-1 font-medium">
                <li>Go to <a href="https://login.yahoo.com/account/security" target="_blank" rel="noreferrer" className="underline font-semibold hover:text-purple-900 dark:hover:text-purple-350">Yahoo Account Security</a></li>
                <li>Click "Generate app password"</li>
                <li>Select app: "Mail" → Copy the 16-character password</li>
                <li>Paste it below (no spaces)</li>
              </ol>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fadeIn">
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">Client Name Reference</label>
              <input
                id="imap-client-name"
                type="text"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
                placeholder="e.g. Acme Corp Inc"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 focus:border-indigo-600 focus:bg-white rounded-lg text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:focus:bg-slate-800/80 transition-all focus:outline-hidden"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">Email Address (Login)</label>
              <input
                id="imap-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={imapProvider === "yahoo" ? "e.g. username@yahoo.com" : "e.g. sync@acme.com"}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 focus:border-indigo-600 focus:bg-white rounded-lg text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:focus:bg-slate-800/80 transition-all focus:outline-hidden"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">IMAP Host Address</label>
              <input
                id="imap-host"
                type="text"
                value={imapHost}
                onChange={(e) => setImapHost(e.target.value)}
                placeholder={imapProvider === "yahoo" ? "imap.mail.yahoo.com" : "e.g. imap.gmail.com"}
                readOnly={imapProvider !== "generic"}
                className={`w-full px-3 py-2 bg-slate-50 border border-slate-200 focus:border-indigo-600 focus:bg-white rounded-lg text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:focus:bg-slate-800/80 transition-all focus:outline-hidden ${
                  imapProvider !== "generic" ? "opacity-75 cursor-not-allowed" : ""
                }`}
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">IMAP Port</label>
                <input
                  id="imap-port"
                  type="number"
                  value={imapPort}
                  onChange={(e) => setImapPort(e.target.value)}
                  placeholder="993"
                  readOnly={imapProvider !== "generic"}
                  className={`w-full px-3 py-2 bg-slate-50 border border-slate-200 focus:border-indigo-600 focus:bg-white rounded-lg text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:focus:bg-slate-800/80 transition-all focus:outline-hidden ${
                    imapProvider !== "generic" ? "opacity-75 cursor-not-allowed" : ""
                  }`}
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block font-mono">Security Password</label>
                <input
                  id="imap-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={imapProvider === "yahoo" ? "16-char App Password" : "••••••••"}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 focus:border-indigo-600 focus:bg-white rounded-lg text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:focus:bg-slate-800/80 transition-all focus:outline-hidden"
                />
              </div>
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              id="imap-submit-btn"
              type="submit"
              disabled={submitting}
              className="px-4 py-2 text-xs font-bold rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white transition-colors cursor-pointer active:scale-95 shadow-xs"
            >
              {submitting ? "Testing Connection..." : "Register Fallback Connection"}
            </button>
          </div>
        </form>
      )}

      {/* Directory Grid of connected sources */}
      {loading ? (
        <div className="text-center py-12 bg-white dark:bg-slate-900/40 backdrop-blur-md rounded-2xl border border-slate-200/60 dark:border-slate-700/50 shadow-xs">
          <div className="animate-spin inline-block h-6 w-6 border-2 border-indigo-600 dark:border-indigo-400 border-t-transparent rounded-full mb-2" />
          <p className="text-xs text-slate-400 dark:text-slate-500 font-medium font-mono">Synchronizing mailbox list...</p>
        </div>
      ) : clients.length === 0 ? (
        <div className="text-center py-16 bg-white dark:bg-slate-900/40 backdrop-blur-md rounded-2xl border border-slate-200/60 dark:border-slate-700/50 border-dashed max-w-4xl mx-auto p-6 space-y-3 animate-fadeIn shadow-xs">
          <Layers className="h-10 w-10 text-slate-350 dark:text-slate-650 mx-auto" />
          <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200">No Mailbox Sources Connected</h3>
          <p className="text-xs text-slate-450 dark:text-slate-400 max-w-md mx-auto leading-relaxed">Authorize the system to pull incoming emails securely by linking a Google Gmail Inbox via Google OAuth 2.0 API or custom IMAP fallback passwords.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {clients.map((client) => (
            <div 
              key={client.id}
              className="bg-white dark:bg-slate-900/40 backdrop-blur-md rounded-2xl border border-slate-200/60 dark:border-slate-700/50 p-5 hover:shadow-xs transition-all flex flex-col justify-between shadow-xs relative overflow-hidden group"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate max-w-[140px] sm:max-w-xs">{client.client_name}</h4>
                    <span className="text-[10px] font-mono font-semibold text-slate-400 dark:text-slate-500 block mt-0.5">{client.email}</span>
                  </div>

                  <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide border ${
                    client.status === "connected" 
                      ? "bg-emerald-55/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50" 
                      : "bg-rose-55/10 text-rose-600 dark:text-rose-400 border-rose-200 dark:border-rose-800/50"
                  }`}>
                    {client.status === "connected" ? (
                      <Wifi className="h-2.5 w-2.5 mr-1 text-emerald-600" />
                    ) : (
                      <AlertTriangle className="h-2.5 w-2.5 mr-1 text-rose-600" />
                    )}
                    <span>{client.status}</span>
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 bg-slate-50 dark:bg-slate-800/40 p-3.5 rounded-xl border border-slate-100 dark:border-slate-850 text-xs font-medium text-slate-700 dark:text-slate-300">
                  <div>
                    <p className="text-[9px] uppercase font-bold text-slate-400 dark:text-slate-505 tracking-wider font-mono">Method</p>
                    <p className="text-slate-800 dark:text-slate-200 font-bold uppercase mt-0.5">{client.auth_type}</p>
                  </div>
                  <div>
                    <p className="text-[9px] uppercase font-bold text-slate-400 dark:text-slate-505 tracking-wider font-mono">Provider</p>
                    <p className="text-indigo-600 dark:text-indigo-400 font-bold mt-0.5 capitalize">{client.provider || "unknown"}</p>
                  </div>
                </div>

                {client.last_synced_at && (
                  <div className="flex items-center space-x-1.5 text-[10px] text-slate-400 dark:text-slate-500">
                    <Calendar className="h-3.5 w-3.5 text-slate-400" />
                    <span>Last Synced: {new Date(client.last_synced_at).toLocaleString()}</span>
                  </div>
                )}
              </div>

              <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between">
                <span className="text-[9px] font-mono text-slate-400 dark:text-slate-600">IDRef: {client.id}</span>
                <button
                  id={`delete-client-btn-${client.id}`}
                  onClick={() => handleDeleteClient(client.id)}
                  className="p-1 px-2.5 hover:bg-rose-50 dark:hover:bg-rose-950/20 text-slate-400 hover:text-rose-600 dark:text-slate-500 dark:hover:text-rose-455 border border-transparent hover:border-rose-100 dark:hover:border-rose-900/50 rounded-lg transition-all text-xs font-semibold flex items-center space-x-1 cursor-pointer active:scale-95"
                  title="Remove Connection"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  <span>Disconnect</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}