/**
 * @author 조휘재
 * 작성일: 2026-10-30
 */

import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { storeSignupEmail } from './signupEmailStorage'

const BACKEND_API_BASE_URL = import.meta.env.VITE_BACKEND_API_BASE_URL

/** 응답 JSON의 code. 본문이 없거나 형식이 아니면 빈 문자열이다. */
async function readCode(response) {
  const text = await response.text()
  if (!text) return ''
  try {
    const body = JSON.parse(text)
    return typeof body.code === 'string' ? body.code : ''
  } catch {
    return ''
  }
}

/** 가입 폼의 필수 입력 칸. */
function TextField({ id, label, type, value, onChange, autoComplete }) {
  return (
    <label htmlFor={id} className="grid gap-1.5 text-sm font-medium text-text sm:text-base">
      {label}
      <input
        id={id}
        name={id}
        type={type}
        value={value}
        autoComplete={autoComplete}
        required
        onChange={onChange}
        className="rounded-lg border border-main/25 bg-white px-3 py-2.5 text-base font-normal outline-none focus:border-main focus:ring-2 focus:ring-accent sm:px-4 sm:py-3"
      />
    </label>
  )
}

/** 이메일만 받아 확인 메일을 보낸다. 비밀번호는 코드를 확인한 뒤에 받는다. */
function SignupPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [result, setResult] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    document.title = '회원가입'
  }, [])

  async function handleSubmit(event) {
    event.preventDefault()
    setResult('')
    setSubmitting(true)
    try {
      const response = await fetch(`${BACKEND_API_BASE_URL}/user-service/user/root-signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      })
      const code = await readCode(response)
      if (response.status === 201) {
        const sentTo = email.trim()
        storeSignupEmail(sentTo)
        navigate('/signup/check-email', { replace: true, state: { email: sentTo } })
        return
      }
      if (code === 'INVALID_REQUEST') {
        setResult('이메일 형식을 확인해 주세요.')
        return
      }
      if (code === 'MAIL_DISABLED') {
        setResult('지금은 이 이메일로 가입할 수 없습니다.')
        return
      }
      if (code === 'MAIL_SEND_FAILED') {
        setResult('확인 메일을 보내지 못했습니다. 다시 시도해 주세요.')
        return
      }
      if (code === 'TOO_MANY_REQUESTS') {
        setResult('요청이 많습니다. 잠시 후 다시 시도해 주세요.')
        return
      }
      setResult(response.status === 409 ? '이미 가입된 이메일입니다.' : '회원가입에 실패했습니다.')
    } catch {
      setResult('회원가입에 실패했습니다.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="grid min-h-dvh bg-background text-text lg:grid-cols-2">
      <header className="bg-main px-4 py-8 text-background sm:px-8 sm:py-12 md:px-12 lg:flex lg:flex-col lg:justify-end lg:px-16 lg:py-20">
        <Link to="/" className="block max-w-md text-inherit no-underline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent">
          <p className="text-xs font-semibold text-accent sm:text-sm">룸링크</p>
          <p className="mt-0.5 text-xs text-background/80">Roomlink</p>
          <h1 className="mt-3 text-2xl font-semibold sm:text-3xl md:text-4xl lg:text-5xl">함께 사는 집</h1>
          <p className="mt-2 text-sm text-background/85 sm:text-base md:mt-4">이메일로 룸링크 계정을 만드세요.</p>
        </Link>
      </header>

      <section className="flex min-w-0 items-center px-4 py-8 sm:px-8 sm:py-12 md:px-12 lg:px-16">
        <form onSubmit={handleSubmit} className="grid w-full min-w-0 max-w-md gap-4 sm:gap-5">
          <h2 className="text-xl font-semibold text-main sm:text-2xl">회원가입</h2>
          <p className="text-sm text-text/70 sm:text-base">이메일로 확인 코드를 보냅니다. 코드를 확인한 뒤에 비밀번호를 정하거나 소셜 계정으로 가입합니다.</p>
          <TextField
            id="email"
            label="이메일"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <div className="mt-1 grid gap-2">
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-main px-4 py-3 text-sm font-semibold text-background hover:bg-main/90 disabled:opacity-60 sm:text-base"
            >
              {submitting ? '보내는 중' : '확인 메일 보내기'}
            </button>
            <p className="flex flex-wrap items-baseline justify-center gap-x-1.5 text-sm text-text/70">
              <span>이미 계정이 있으신가요?</span>
              <Link
                to="/login"
                className="font-semibold text-main focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              >
                로그인
              </Link>
            </p>
          </div>
          {result !== '' && (
            <p className="min-w-0 rounded-lg border border-main/20 bg-white p-3 text-sm">{result}</p>
          )}
        </form>
      </section>
    </main>
  )
}

export default SignupPage
