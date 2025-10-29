import React from 'react'

export default function SecurityLog({ logs = [] }) {
  if (!logs.length) {
    return <div className="text-gray-400 text-sm">No recent checks.</div>
  }
  return (
    <div className="space-y-2">
      {logs.map((log, idx) => (
        <div key={`${log.layer}-${idx}`} className="flex items-center justify-between bg-gray-800/50 border border-gray-700 rounded-md px-3 py-2">
          <div className="text-sm">{log.layer}</div>
          <div className={`text-xs px-2 py-0.5 rounded-full ${log.result === 'pass' ? 'bg-emerald-600/30 text-emerald-300' : 'bg-red-600/30 text-red-300'}`}>
            {log.result === 'pass' ? '✅ Pass' : '⚠️ Alert'}
          </div>
        </div>
      ))}
    </div>
  )
}
