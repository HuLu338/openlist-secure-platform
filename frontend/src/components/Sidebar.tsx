import { NavLink } from 'react-router-dom'

export type NavItem = {
  path: string
  label: string
}

type SidebarProps = {
  items: NavItem[]
}

function Sidebar({ items }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">OL</span>
        <div>
          <strong>OpenList Secure Platform</strong>
          <span>Security Management Dashboard</span>
        </div>
      </div>

      <nav className="nav-list" aria-label="Main navigation">
        {items.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            <span className="nav-bullet" />
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}

export default Sidebar
