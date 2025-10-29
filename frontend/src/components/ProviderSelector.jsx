import React from 'react'

export default function ProviderSelector({ value, onChange, options = [] }) {
  return (
    <div className="flex items-center gap-2">
      <label className="text-sm text-gray-300">Provider:</label>
      <select
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-md px-2 py-1 text-emerald-200 focus:outline-none focus:border-emerald-500"
      >
        {options.map(opt => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
    </div>
  )
}
