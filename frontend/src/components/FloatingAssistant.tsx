import { useState } from 'react'
import { chatWithAssistant } from '../api/api'
import type { AssistantChatResponse } from '../types/types'
import Badge from './Badge'

type FloatingMessage = {
  id: number
  role: 'user' | 'assistant'
  text: string
  response?: AssistantChatResponse
}

const quickQuestions = [
  'What is the current security status?',
  'Why is the latest scan score low?',
  'What should I fix first?',
  'Explain the latest alert',
  'Are there suspicious API activities?',
]

function FloatingAssistant() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<FloatingMessage[]>([])
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function sendMessage(nextMessage = message) {
    const trimmedMessage = nextMessage.trim()
    if (!trimmedMessage) {
      return
    }

    setOpen(true)
    setMessage('')
    setError('')
    setLoading(true)

    const userMessage: FloatingMessage = {
      id: Date.now(),
      role: 'user',
      text: trimmedMessage,
    }
    setMessages((current) => [...current, userMessage])

    try {
      const response = await chatWithAssistant(trimmedMessage)
      setMessages((current) => [
        ...current,
        {
          id: Date.now() + 1,
          role: 'assistant',
          text: response.answer,
          response,
        },
      ])
    } catch {
      setError('Assistant request failed. Check backend status and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      {open ? (
        <section className="floating-assistant-panel" aria-label="AI Security Assistant">
          <header className="floating-assistant-header">
            <div>
              <strong>AI Security Assistant</strong>
              <span>Connected to backend</span>
            </div>
            <button
              type="button"
              className="secondary floating-assistant-close"
              onClick={() => setOpen(false)}
              aria-label="Close assistant"
            >
              x
            </button>
          </header>

          <div className="floating-assistant-body">
            {messages.length === 0 ? (
              <p className="empty-state">Ask about scans, alerts, recommendations, rules, or audit logs.</p>
            ) : (
              messages.map((item) => (
                <div key={item.id} className={`floating-message floating-message-${item.role}`}>
                  <p>{item.text}</p>
                  {item.response ? <FloatingResponse response={item.response} /> : null}
                </div>
              ))
            )}
            {loading ? <p className="muted">Assistant is thinking...</p> : null}
            {error ? <p className="error">{error}</p> : null}
          </div>

          <div className="floating-quick-questions">
            {quickQuestions.map((question) => (
              <button
                key={question}
                type="button"
                className="secondary floating-chip"
                disabled={loading}
                onClick={() => sendMessage(question)}
              >
                {question}
              </button>
            ))}
          </div>

          <footer className="floating-assistant-footer">
            <input
              value={message}
              placeholder="Ask a security question..."
              onChange={(event) => setMessage(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  sendMessage()
                }
              }}
            />
            <button type="button" disabled={loading || !message.trim()} onClick={() => sendMessage()}>
              Send
            </button>
          </footer>
        </section>
      ) : null}

      <button
        type="button"
        className="floating-assistant-button"
        onClick={() => setOpen((current) => !current)}
        aria-label="Open AI assistant"
      >
        <span aria-hidden="true">🤖</span>
      </button>
    </>
  )
}

function FloatingResponse({ response }: { response: AssistantChatResponse }) {
  return (
    <div className="floating-response-details">
      <div className="featured-meta">
        <Badge tone={response.mode === 'openai' ? 'platform' : 'success'}>{response.mode}</Badge>
      </div>

      {response.sources.length > 0 ? (
        <div className="floating-source-list">
          {response.sources.map((source) => (
            <Badge key={source} tone="platform">
              {source}
            </Badge>
          ))}
        </div>
      ) : null}

      {response.suggested_actions.length > 0 ? (
        <ul className="floating-actions-list">
          {response.suggested_actions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

export default FloatingAssistant
