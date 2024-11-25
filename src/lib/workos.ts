import { WorkOS } from "@workos-inc/node";
import type { AstroCookies } from "astro";

export const workos = new WorkOS(import.meta.env.WORKOS_API_KEY, {
  clientId: import.meta.env.WORKOS_CLIENT_ID,
});

const getSession = async (cookies: AstroCookies) => {
  const cookieSession = cookies.get("wos-session");

  const session = workos.userManagement.loadSealedSession({
    sessionData: cookieSession?.value as string,
    cookiePassword: import.meta.env.WORKOS_COOKIE_PASSWORD,
  });

  return await session.authenticate();
}

export const isAuthenticated = async (cookies: AstroCookies) => {
  const result = await getSession(cookies);
  return result.authenticated;
};

export const getUser = async (cookies: AstroCookies) => {
  const result = await getSession(cookies);
  if (result.authenticated) {
    return result.user;
  }
  return null;
};
