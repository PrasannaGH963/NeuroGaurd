import React, { useState } from 'react'

export default function ChatInput({ onSend, disabled }) {
  const [value, setValue] = useState('')

  const submit = () => {
    const v = value.trim()
    if (!v) return
    onSend?.(v)
    setValue('')
  }

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      submit()
    }
  }

  return (
    <div className="flex items-center gap-2">
      <textarea
        className="flex-1 resize-none rounded-lg bg-gray-800/70 border border-gray-700 focus:border-emerald-500 focus:outline-none p-3 text-emerald-200 shadow-inner min-h-[48px]"
        placeholder="Ask something…"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={onKeyDown}
        disabled={disabled}
        rows={1}
      />
      <button
        onClick={submit}
        disabled={disabled}
        className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-gray-950 font-semibold shadow-lg"
      >
        Send
      </button>
    </div>
  )
}
