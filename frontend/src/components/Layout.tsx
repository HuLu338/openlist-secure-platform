import type { ReactNode } from 'react'
import FloatingAssistant from './FloatingAssistant'
import Sidebar, { type NavItem } from './Sidebar'
import TopHeader from './TopHeader'

type LayoutProps = {
  activeTitle: string
  apiOnline: boolean
  children: ReactNode
  navItems: NavItem[]
}

function Layout({ activeTitle, apiOnline, children, navItems }: LayoutProps) {
  return (
    <div className="app-shell">
      <Sidebar items={navItems} />
      <div className="content-shell">
        <TopHeader title={activeTitle} apiOnline={apiOnline} />
        <main className="main-content">{children}</main>
      </div>
      <FloatingAssistant />
    </div>
  )
}

export default Layout
