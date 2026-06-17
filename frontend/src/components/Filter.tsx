import type { FormEvent } from 'react'

export type FilterField = {
  name: string
  label: string
  placeholder?: string
}

type FilterProps = {
  fields: FilterField[]
  values: Record<string, string>
  onChange: (name: string, value: string) => void
  onSubmit: () => void
  onReset?: () => void
}

function Filter({ fields, values, onChange, onSubmit, onReset }: FilterProps) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onSubmit()
  }

  return (
    <form className="filter-form" onSubmit={handleSubmit}>
      {fields.map((field) => (
        <label key={field.name}>
          <span>{field.label}</span>
          <input
            value={values[field.name] ?? ''}
            placeholder={field.placeholder}
            onChange={(event) => onChange(field.name, event.target.value)}
          />
        </label>
      ))}
      <div className="actions">
        <button type="submit">Apply</button>
        {onReset ? (
          <button type="button" className="secondary" onClick={onReset}>
            Reset
          </button>
        ) : null}
      </div>
    </form>
  )
}

export default Filter
