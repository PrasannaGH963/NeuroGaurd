import React from 'react'

export default function ChatMessage({ message }) {
  const { role, content, status } = message

  if (status === 'alert') {
    return (
      <div className="border border-red-600/50 bg-red-900/20 text-red-300 rounded-lg p-3">
        <div className="font-semibold mb-1">⚠️ Alert</div>
        <div className="whitespace-pre-wrap">{content}</div>
      </div>
    )
  }

  const isUser = role === 'user'
  const bubbleClass = isUser
    ? 'bg-gray-800/60 border-gray-700 text-emerald-200'
    : 'bg-emerald-900/20 border-emerald-700 text-emerald-200'

  return (
    <div className={`w-full flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div className={`max-w-[80%] border rounded-lg p-3 shadow ${bubbleClass}`}>
        <div className="text-xs opacity-70 mb-1">{isUser ? 'You' : 'Assistant'}</div>
        <div className="whitespace-pre-wrap leading-relaxed">{content}</div>
      </div>
    </div>
  )
}
