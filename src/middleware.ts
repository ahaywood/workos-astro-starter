import type { APIContext, MiddlewareNext } from 'astro';
import { workos } from './lib/workos';

async function withAuth(context: APIContext, next: MiddlewareNext) {
  const { cookies, redirect } = context;

  const session = workos.userManagement.loadSealedSession({
    sessionData: cookies.get('wos-session')?.value as string,
    cookiePassword: import.meta.env.WORKOS_COOKIE_PASSWORD,
  });

  const result = await session.authenticate();

  if (result.authenticated) {
    return next();
  }

  // If the cookie is missing, redirect to login
  if (!result.authenticated && result.reason === 'no_session_cookie_provided') {
    return redirect('/login');
  }

  // If the session is invalid, attempt to refresh
  try {
    const result = await session.refresh();

    if (!result.authenticated) {
      return redirect('/login');
    }

    // update the cookie
    cookies.set('wos-session', result.sealedSession as string, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
    });

    // Redirect to the same route to ensure the updated cookie is used
    return redirect(context.url.pathname);
  } catch (e) {
    // Failed to refresh access token, redirect user to login page
    // after deleting the cookie
    cookies.delete('wos-session');
    return redirect('/login');
  }
}

export async function onRequest(context: any, next: any) {
  // intercept data from a request
  // optionally, modify the properties in `locals`
  if (context.url.pathname.startsWith('/admin/')) {
    return await withAuth(context, next);
  } else {
    // return a Response or the result of calling `next()`
    return next();
  }
};