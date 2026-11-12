import { useEffect, useState } from "react";
import { CheckCircle2, AlertTriangle, Fingerprint, MailCheck, ShieldCheck, Loader2 } from "lucide-react";

type Invitation = {client_name: string; email: string; provider: "google" | "microsoft"; status: string; expires_at: string};

export default function ClientAuthorization() {
  const pathname = window.location.pathname;
  const isResult = pathname === "/connect/result";
  const token = !isResult && pathname.startsWith("/connect/") ? pathname.slice("/connect/".length) : "";
  const [inv, setInv] = useState<Invitation | null>(null);
  const [loading, setLoading] = useState(!isResult);
  const [error, setError] = useState("");
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const params = new URLSearchParams(window.location.search);
  const successful = isResult && params.get("status") === "success";

  useEffect(() => {
    if (isResult) return;
    let cancelled = false;
    if (!/^[a-zA-Z0-9_-]{32,128}$/.test(token)) {
      setError("This connection link is invalid.");
      setLoading(false);
      return;
    }
    fetch(`/api/client-authorization/invitation/${encodeURIComponent(token)}`, {cache: "no-store", credentials: "omit"})
      .then(async (r) => {
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || "Unable to load the connection link.");
        return data as Invitation;
      })
      .then((data) => {if (!cancelled) setInv(data);})
      .catch((e) => {if (!cancelled) setError(e.message || "Connection unavailable.");})
      .finally(() => {if (!cancelled) setLoading(false);});
    return () => {cancelled = true;};
  }, [token, isResult]);

  async function startConnection() {
    if (!inv || !consent || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`/api/client-authorization/invitation/${encodeURIComponent(token)}/start`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        credentials: "omit", cache: "no-store", body: JSON.stringify({consent: true}),
      });
      const data = await response.json();
      if (!response.ok || !data.url) throw new Error(data.error || "Unable to begin connection.");
      window.location.assign(data.url);
    } catch (e: any) {
      setError(e?.message || "Connection could not be started. Please retry.");
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 flex items-center justify-center p-4 text-slate-800">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-2xl overflow-hidden">
        <header className="px-7 py-6 bg-slate-900 text-white flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-indigo-600 flex items-center justify-center"><MailCheck className="h-5 w-5"/></div>
          <div><h1 className="font-bold text-base">WeApplying4U</h1><p className="text-xs text-slate-300">Secure email authorization</p></div>
        </header>
        <div className="p-7 space-y-5">
          {isResult ? (
            <div className="text-center space-y-4 py-5">
              {successful ? <CheckCircle2 className="h-12 w-12 text-emerald-600 mx-auto"/> : <AlertTriangle className="h-12 w-12 text-amber-600 mx-auto"/>}
              <h2 className="text-xl font-bold">{successful ? "Your email is connected" : "Connection not completed"}</h2>
              <p className="text-sm text-slate-600">{successful
                ? "Your email authorization was verified. You may close this page. WeApplying4U will notify your administrator through the dashboard."
                : "Your mailbox was not connected. Return to your original invitation link and try again, or ask your administrator for a new link."}</p>
              <p className="text-xs text-slate-500">Your fingerprint, PIN and passkey remain with your own device and email provider.</p>
            </div>
          ) : loading ? (
            <div className="flex items-center gap-2 text-slate-600 py-8 justify-center"><Loader2 className="w-5 h-5 animate-spin"/> Checking invitation…</div>
          ) : !inv ? (
            <div role="alert" className="bg-red-50 text-red-700 p-4 rounded-lg text-sm">{error || "Connection link unavailable."}</div>
          ) : inv.status !== "pending" ? (
            <div className="text-center space-y-3 py-6">
              {inv.status === "connected" ? <CheckCircle2 className="h-10 w-10 text-emerald-600 mx-auto"/> : <AlertTriangle className="h-10 w-10 text-amber-600 mx-auto"/>}
              <h2 className="font-bold">{inv.status === "connected" ? "Already connected" : "This invitation is no longer active"}</h2>
              <p className="text-sm text-slate-600">{inv.status === "connected" ? "You have already completed this authorization." : "Please ask your WeApplying4U administrator for a fresh link."}</p>
            </div>
          ) : (
            <>
              <div className="space-y-2">
                <div className="flex gap-2 items-center"><Fingerprint className="h-5 w-5 text-indigo-600"/><h2 className="text-lg font-bold">Connect your email securely</h2></div>
                <p className="text-sm text-slate-600">Complete this step on your own phone or laptop. Sign in to your provider using your usual fingerprint, face recognition, passkey or PIN.</p>
              </div>
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <p className="text-[11px] uppercase font-semibold tracking-wide text-slate-500">Account requested for {inv.client_name}</p>
                <p className="font-bold break-all">{inv.email}</p>
                <p className="text-xs text-slate-500">{inv.provider === "google" ? "Google / Gmail" : "Microsoft / Hotmail / Outlook"}</p>
                <p className="text-xs text-slate-500">Link expires {new Date(inv.expires_at).toLocaleString()}</p>
              </div>
              <div className="rounded-xl bg-indigo-50 text-slate-700 p-4 space-y-2 text-sm">
                <div className="flex items-center gap-2 font-bold"><ShieldCheck className="h-4 w-4 text-indigo-700"/> What you are authorizing</div>
                <p>WeApplying4U will receive read-only access to your mailbox to collect job application OTPs and verification messages. The current system may also process other incoming messages, and authorized administrators may review them. Email content on the website is normally deleted after 30 minutes.</p>
                <p>You can revoke access in your Google or Microsoft account settings. You do not need to share your password or fingerprint with our staff.</p>
              </div>
              <label className="flex items-start gap-3 text-sm text-slate-700 cursor-pointer">
                <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} className="mt-1 accent-indigo-600"/>
                <span>I understand the mailbox access described above and agree to connect <strong>{inv.email}</strong>.</span>
              </label>
              {error && <div role="alert" className="p-3 rounded-lg bg-red-50 text-red-700 text-sm"><AlertTriangle className="w-4 h-4 inline mr-2"/>{error}</div>}
              <button type="button" disabled={!consent || busy} onClick={startConnection}
                className="w-full rounded-lg px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed">
                {busy ? "Opening secure sign-in…" : `Continue with ${inv.provider === "google" ? "Google" : "Microsoft"}`}
              </button>
              <p className="text-[11px] text-center text-slate-500">Only the email address assigned to this invitation will be accepted.</p>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
