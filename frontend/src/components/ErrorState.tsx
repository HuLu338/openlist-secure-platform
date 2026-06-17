type ErrorStateProps = {
  message: string
}

function ErrorState({ message }: ErrorStateProps) {
  return <p className="error">{message}</p>
}

export default ErrorState
