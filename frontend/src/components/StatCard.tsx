type StatCardProps = {
  title: string
  value: string | number
  hint?: string
}

function StatCard({ title, value, hint }: StatCardProps) {
  return (
    <section className="card metric-card">
      <h2>{title}</h2>
      <p className="metric-large">{value}</p>
      {hint ? <p className="muted">{hint}</p> : null}
    </section>
  )
}

export default StatCard
