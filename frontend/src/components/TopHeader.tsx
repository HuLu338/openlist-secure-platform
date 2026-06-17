type TopHeaderProps = {
  title: string
  apiOnline: boolean
}

function TopHeader({ title, apiOnline }: TopHeaderProps) {
  return (
    <header className="top-header">
      <div>
        <span className="eyebrow">Platform: OpenList</span>
        <strong>{title}</strong>
      </div>
      <div
        className={`api-status ${apiOnline ? 'api-status-online' : 'api-status-offline'}`}
        title={apiOnline ? 'Backend health check passed' : 'Backend health check failed'}
      >
        <span className="status-dot" />
        API {apiOnline ? 'online' : 'offline'}
      </div>
    </header>
  )
}

export default TopHeader
