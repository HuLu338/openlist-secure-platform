import { useState } from 'react'

export type ChartDataPoint = {
  label: string
  value: number
}

type ChartProps = {
  title?: string
  data?: ChartDataPoint[]
  variant?: 'bar' | 'line' | 'pie'
}

const colors = ['#347b5c', '#d78a33', '#b94e48', '#5271a7', '#6d8a42', '#8f5d9f']

function Chart({ title = 'Chart', data = [], variant = 'bar' }: ChartProps) {
  const [selectedPoint, setSelectedPoint] = useState<ChartDataPoint | null>(null)
  const [hoveredPoint, setHoveredPoint] = useState<ChartDataPoint | null>(null)
  const maxValue = Math.max(...data.map((item) => item.value), 1)
  const activePoint = hoveredPoint ?? selectedPoint

  return (
    <div className="chart">
      <strong>{title}</strong>
      {data.length === 0 ? (
        <p className="muted">No chart data available yet.</p>
      ) : variant === 'line' ? (
        <LineChart
          data={data}
          maxValue={maxValue}
          onHover={setHoveredPoint}
          onSelect={setSelectedPoint}
        />
      ) : variant === 'pie' ? (
        <PieChart data={data} onHover={setHoveredPoint} onSelect={setSelectedPoint} />
      ) : (
        <div className="chart-bars">
          {data.map((item) => (
            <div className="chart-row" key={item.label}>
              <span>{item.label}</span>
              <button
                type="button"
                className="bar-track chart-button"
                onMouseEnter={() => setHoveredPoint(item)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => setSelectedPoint(item)}
                title={`${item.label}: ${item.value}`}
              >
                <div
                  className="bar-fill"
                  style={{ width: `${Math.max((item.value / maxValue) * 100, 4)}%` }}
                />
              </button>
              <b>{item.value}</b>
            </div>
          ))}
        </div>
      )}
      {activePoint ? (
        <p className="chart-detail">
          {hoveredPoint ? 'Hovering' : 'Selected'} {activePoint.label}:{' '}
          <strong>{activePoint.value}</strong>
        </p>
      ) : null}
    </div>
  )
}

function LineChart({
  data,
  maxValue,
  onSelect,
  onHover,
}: {
  data: ChartDataPoint[]
  maxValue: number
  onHover: (item: ChartDataPoint | null) => void
  onSelect: (item: ChartDataPoint) => void
}) {
  const width = 520
  const height = 180
  const padding = 24
  const points = data.map((item, index) => {
    const x =
      data.length === 1
        ? width / 2
        : padding + (index / (data.length - 1)) * (width - padding * 2)
    const y = height - padding - (item.value / maxValue) * (height - padding * 2)
    return { ...item, x, y }
  })
  const polylinePoints = points.map((point) => `${point.x},${point.y}`).join(' ')

  return (
    <div className="line-chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="line chart">
        <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} />
        <polyline points={polylinePoints} />
        {points.map((point) => (
          <g
            key={point.label}
            onClick={() => onSelect(point)}
            onMouseEnter={() => onHover(point)}
            onMouseLeave={() => onHover(null)}
            tabIndex={0}
          >
            <circle cx={point.x} cy={point.y} r="4" />
            <title>
              {point.label}: {point.value}
            </title>
            <text x={point.x} y={height - 6}>
              {point.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

function PieChart({
  data,
  onSelect,
  onHover,
}: {
  data: ChartDataPoint[]
  onHover: (item: ChartDataPoint | null) => void
  onSelect: (item: ChartDataPoint) => void
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  let current = 0
  const gradient =
    total === 0
      ? '#e1e8de'
      : `conic-gradient(${data
          .map((item, index) => {
            const start = current
            const size = (item.value / total) * 100
            current += size
            return `${colors[index % colors.length]} ${start}% ${current}%`
          })
          .join(', ')})`

  return (
    <div className="pie-chart">
      <div className="pie-visual" style={{ background: gradient }} aria-hidden="true" />
      <div className="pie-legend">
        {data.map((item, index) => (
          <button
            type="button"
            className="pie-legend-item"
            key={item.label}
            onMouseEnter={() => onHover(item)}
            onMouseLeave={() => onHover(null)}
            onClick={() => onSelect(item)}
            title={`${item.label}: ${item.value}`}
          >
            <i style={{ background: colors[index % colors.length] }} />
            {item.label}: {item.value}
          </button>
        ))}
      </div>
    </div>
  )
}

export default Chart
