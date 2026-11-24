import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { tenantHomeUrl } from '../../tenantHost'

const BACKEND_API_BASE_URL = import.meta.env.VITE_BACKEND_API_BASE_URL

/** 목록 항목에서 이름과 주소 이름만 남긴다. */
function readTenants(body) {
  if (!Array.isArray(body)) return []
  return body.flatMap((item) => {
    const name = typeof item?.name === 'string' ? item.name.trim() : ''
    const slug = typeof item?.slug === 'string' ? item.slug.trim() : ''
    return name && slug ? [{ name, slug }] : []
  })
}

/** 로그인한 회원의 테넌트. 없으면 생성 화면으로 보낸다. */
function TenantSelectPage() {
  const navigate = useNavigate()
  const [tenants, setTenants] = useState([])
  const [notice, setNotice] = useState('')
  const [status, setStatus] = useState('loading')
  const [entering, setEntering] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      try {
        const response = await fetch(`${BACKEND_API_BASE_URL}/user-service/user/tenants`, {
          credentials: 'include',
          signal: controller.signal,
        })
        if (response.status === 401) {
          navigate('/login', { replace: true })
          return
        }
        if (!response.ok) {
          setNotice('테넌트 목록을 불러오지 못했습니다.')
          setStatus('ready')
          return
        }
        const tenants = readTenants(await response.json().catch(() => null))
        if (tenants.length === 0) {
          navigate('/tenants/new', { replace: true })
          return
        }
        setTenants(tenants)
        setStatus('ready')
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') return
        setNotice('테넌트 목록을 불러오지 못했습니다.')
        setStatus('ready')
      }
    }

    load()
    return () => controller.abort()
  }, [navigate])

  async function enter(slug) {
    setNotice('')
    setEntering(slug)
    try {
      const response = await fetch(`${BACKEND_API_BASE_URL}/user-service/user/tenant-entry`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ tenant: slug }),
      })
      if (response.status === 204) {
        window.location.assign(tenantHomeUrl(slug, window.location))
        return
      }
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      setNotice(response.status === 403 ? '이 테넌트에 들어갈 수 없습니다.' : '테넌트에 들어가지 못했습니다.')
    } catch {
      setNotice('테넌트에 들어가지 못했습니다.')
    } finally {
      setEntering('')
    }
  }

  useEffect(() => {
    document.title = '테넌트 선택'
  }, [])

  return (
    <main className="grid min-h-dvh bg-background text-text lg:grid-cols-2">
      <header className="bg-main px-4 py-8 text-background sm:px-8 sm:py-12 md:px-12 lg:flex lg:flex-col lg:justify-end lg:px-16 lg:py-20">
        <Link to="/" className="block max-w-md text-inherit no-underline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent">
          <p className="text-xs font-semibold text-accent sm:text-sm">룸링크</p>
          <p className="mt-0.5 text-xs text-background/80">Roomlink</p>
          <h1 className="mt-3 text-2xl font-semibold sm:text-3xl md:text-4xl lg:text-5xl">함께 사는 집</h1>
          <p className="mt-2 text-sm text-background/85 sm:text-base md:mt-4">들어갈 테넌트를 고르세요.</p>
        </Link>
      </header>

      <section className="flex min-w-0 items-center px-4 py-8 sm:px-8 sm:py-12 md:px-12 lg:px-16">
        <div className="grid w-full min-w-0 max-w-md gap-4 sm:gap-5">
          <h2 className="text-xl font-semibold text-main sm:text-2xl">테넌트 선택</h2>
          {status === 'loading' ? (
            <p className="text-sm text-text/70 sm:text-base">테넌트를 확인하고 있습니다.</p>
          ) : (
            <ul className="grid gap-2">
              {tenants.map((tenant) => (
                <li key={tenant.slug}>
                  <button
                    type="button"
                    disabled={entering !== ''}
                    onClick={() => enter(tenant.slug)}
                    className="grid w-full gap-0.5 rounded-lg border border-main/25 bg-white px-4 py-3 text-left hover:bg-main/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:opacity-60"
                  >
                    <span className="text-sm font-semibold text-main sm:text-base">{tenant.name}</span>
                    <span className="text-xs text-text/70">{tenant.slug}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {notice !== '' && (
            <p className="min-w-0 rounded-lg border border-main/20 bg-white p-3 text-sm">{notice}</p>
          )}
        </div>
      </section>
    </main>
  )
}

export default TenantSelectPage
