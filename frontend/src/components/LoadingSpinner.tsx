type LoadingSpinnerProps = {
  label?: string
}

function LoadingSpinner({ label = 'Loading...' }: LoadingSpinnerProps) {
  return (
    <div className="loading-spinner" role="status" aria-live="polite">
      <span className="spinner-dot" />
      <span>{label}</span>
    </div>
  )
}

export default LoadingSpinner
