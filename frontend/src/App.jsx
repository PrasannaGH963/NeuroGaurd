import React, { useEffect, useMemo, useState } from 'react'
import ChatInput from './components/ChatInput.jsx'
import ChatMessage from './components/ChatMessage.jsx'
import SecurityLog from './components/SecurityLog.jsx'
import ProviderSelector from './components/ProviderSelector.jsx'

const BACKEND_BASE = 'http://localhost:8000'

export default function App() {
  const [provider, setProvider] = useState('openai')
  const [providers, setProviders] = useState(['openai', 'gemini', 'claude'])
  const [messages, setMessages] = useState([]) // {role: 'user'|'assistant'|'system', content, status?, reason?, logs?}
  const [processing, setProcessing] = useState(false)
  const [securityLogHistory, setSecurityLogHistory] = useState([]) // Array of {prompt, logs, timestamp, status}

  useEffect(() => {
    // Fetch provider list from backend
    fetch(`${BACKEND_BASE}/api/config`).then(r => r.json()).then(data => {
      if (Array.isArray(data.providers)) setProviders(data.providers)
    }).catch(() => {})
  }, [])

  const handleSend = async (prompt) => {
    if (!prompt || !prompt.trim()) return

    setMessages(prev => [...prev, { role: 'user', content: prompt }])
    setProcessing(true)

    try {
      const res = await fetch(`${BACKEND_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, provider })
      })
      const data = await res.json()

      // Add to security log history
      setSecurityLogHistory(prev => {
        const newEntry = {
          prompt: prompt.substring(0, 50) + (prompt.length > 50 ? '...' : ''),
          logs: data.logs || [],
          timestamp: new Date().toLocaleTimeString(),
          status: data.status
        }
        return [newEntry, ...prev].slice(0, 20) // Keep last 20 entries
      })

      if (data.status === 'ok') {
        setMessages(prev => [...prev, { role: 'assistant', content: data.response, status: 'ok', logs: data.logs }])
      } else {
        setMessages(prev => [...prev, { role: 'system', content: data.reason || 'Alert triggered', status: 'alert', logs: data.logs }])
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: 'system', content: 'Network error contacting backend', status: 'alert' }])
    } finally {
      setProcessing(false)
    }
  }

  const rightPanel = useMemo(() => (
    <div className="w-full h-full overflow-y-auto p-4 space-y-3 scrollbar-thin">
      <h2 className="text-emerald-300 text-lg mb-2">Security Log History</h2>
      {securityLogHistory.length === 0 ? (
        <div className="text-gray-400 text-sm">No recent checks.</div>
      ) : (
        <div className="space-y-4">
          {securityLogHistory.map((entry, idx) => (
            <div key={idx} className="bg-gray-800/30 border border-gray-700 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs text-gray-400 truncate flex-1" title={entry.prompt}>
                  "{entry.prompt}"
                </div>
                <div className={`text-xs px-2 py-0.5 rounded-full ml-2 ${
                  entry.status === 'ok' ? 'bg-emerald-600/30 text-emerald-300' : 'bg-red-600/30 text-red-300'
                }`}>
                  {entry.status === 'ok' ? '✓' : '⚠'}
                </div>
              </div>
              <div className="text-xs text-gray-500 mb-2">{entry.timestamp}</div>
              <SecurityLog logs={entry.logs} />
            </div>
          ))}
        </div>
      )}
    </div>
  ), [securityLogHistory])

  return (
    <div className="min-h-screen flex flex-col">
      <header className="p-4 border-b border-gray-800 bg-gray-900/50 backdrop-blur">
        <div className="max-w-6xl mx-auto flex items-center gap-4">
          <div className="text-emerald-400 font-bold">NeuroGuard</div>
          <ProviderSelector value={provider} onChange={setProvider} options={providers} />
        </div>
      </header>

      <main className="flex-1 max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-3 gap-4 p-4">
        <div className="lg:col-span-2 flex flex-col bg-gray-900 text-emerald-200 p-4 rounded-xl shadow-glow border border-gray-800">
          <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-thin">
            {messages.length === 0 && (
              <div className="text-gray-400">Type a prompt to begin…</div>
            )}
            {messages.map((m, idx) => (
              <ChatMessage key={idx} message={m} />
            ))}
            {processing && (
              <div className="text-sm text-emerald-300 animate-pulse">Processing…</div>
            )}
          </div>
          <div className="mt-4">
            <ChatInput disabled={processing} onSend={handleSend} />
          </div>
        </div>
        <aside className="bg-gray-900 text-emerald-200 rounded-xl shadow-glow border border-gray-800 min-h-[300px]">
          {rightPanel}
        </aside>
      </main>
    </div>
  )
}
