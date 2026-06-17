import type { ReactNode } from 'react'

type CardProps = {
  title?: string
  subtitle?: string
  children: ReactNode
  className?: string
}

function Card({ title, subtitle, children, className = '' }: CardProps) {
  return (
    <section className={`card ${className}`.trim()}>
      {title ? (
        <div className="card-header">
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      ) : null}
      {children}
    </section>
  )
}

export default Card
