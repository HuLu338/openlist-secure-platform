type EmptyStateProps = {
  message?: string
}

function EmptyState({ message = 'No data available yet.' }: EmptyStateProps) {
  return <p className="empty-state">{message}</p>
}

export default EmptyState
