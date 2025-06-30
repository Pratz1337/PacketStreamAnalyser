import { NextRequest, NextResponse } from 'next/server'
// Remove the crypto import as it's not supported in Edge Runtime

export function middleware(request: NextRequest) {
  // Generate a nonce for Content Security Policy using Web Crypto API
  // The crypto object is globally available in Edge Runtime
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64")

  // Create a Content Security Policy that allows connections to the Flask backend
  const cspHeader = `
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' blob: data: http://localhost:5000;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    connect-src 'self' http://localhost:5000;
  `

  // Replace newline characters and spaces
  const contentSecurityPolicyHeaderValue = cspHeader.replace(/\s{2,}/g, " ").trim()

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set("x-nonce", nonce)

  // Set security headers
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })

  // Add CSP header to the response
  response.headers.set("Content-Security-Policy", contentSecurityPolicyHeaderValue)

  return response
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
}
