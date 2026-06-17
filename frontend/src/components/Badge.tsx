type BadgeProps = {
  children: string | number | boolean
  tone?: string
}

function Badge({ children, tone }: BadgeProps) {
  const label = String(children)
  const normalizedTone = (tone ?? label).toLowerCase().replace(/[^a-z0-9]+/g, '-')

  return <span className={`badge badge-${normalizedTone}`}>{label}</span>
}

export default Badge
