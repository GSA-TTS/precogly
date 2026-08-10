import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { setTokens } from '@/lib/api'

/**
 * SsoCallback consumes tokens delivered by the backend SSO handoff endpoint.
 *
 * The backend redirects here as `#access=…&refresh=…&pk=…&email=…`. The
 * URL fragment is not sent to any server, so tokens never leave the client.
 * We persist them via `setTokens` and force a full navigation so
 * `AuthContext` re-hydrates the user from `/api/auth/user/`.
 */
export function SsoCallback() {
  const navigate = useNavigate()
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current) return
    ran.current = true
    const hash = window.location.hash.replace(/^#/, '')
    const params = new URLSearchParams(hash)
    const access = params.get('access')
    const refresh = params.get('refresh')
    if (!access || !refresh) {
      navigate('/login?sso=error', { replace: true })
      return
    }
    setTokens(access, refresh)
    // Full document navigation so AuthProvider re-mounts and reads the tokens.
    // Using assign (not replace) guarantees a browser reload of "/".
    window.location.assign('/')
  }, [navigate])

  return (
    <div className="min-h-screen flex items-center justify-center text-muted-foreground">
      Signing you in…
    </div>
  )
}

export default SsoCallback
