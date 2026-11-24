/** 로컬에서 고른 테넌트 첫 화면. 그 밖에서는 앱 홈이다. */
export function tenantHomeUrl(slug, page) {
  const protocol = page.protocol || 'http:'
  const hostname = String(page.hostname ?? '')
  const port = page.port ? `:${page.port}` : ''
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return `${protocol}//${slug}.localhost${port}/`
  }
  return '/'
}

/** 로컬 테넌트 주소의 slug. `localhost` 자체는 빈 문자열이다. */
export function tenantSlug(hostname) {
  const host = String(hostname ?? '').trim().toLowerCase().replace(/\.$/, '')
  const suffix = '.localhost'
  if (!host.endsWith(suffix)) return ''
  const label = host.slice(0, -suffix.length)
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return ''
  return label
}
