import "server-only";

import { randomUUID } from "node:crypto";
import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { betterAuth } from "better-auth";
import { nextCookies } from "better-auth/next-js";
import { anonymous } from "better-auth/plugins";
import { isIdentityAllowed } from "@/src/auth/allowlist";
import { parseRuntimeConfig, type RuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase, type LocalDatabase } from "@/src/db/local";
import { schema } from "@/src/db/schema";
import { getAuthSecret } from "@/src/auth/local-secret";

export function buildAuth(config: RuntimeConfig, database: LocalDatabase, secret: string) {
  const appStore = new AppStore(database);
  const google = config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET
    ? {
        google: {
          clientId: config.GOOGLE_CLIENT_ID,
          clientSecret: config.GOOGLE_CLIENT_SECRET,
          scope: ["openid", "email", "profile"]
        }
      }
    : {};

  return betterAuth({
    appName: "Crossbeam TW",
    baseURL: config.APP_ORIGIN,
    basePath: "/api/auth",
    secret,
    trustedOrigins: [config.APP_ORIGIN],
    database: drizzleAdapter(database.db, {
      provider: "sqlite",
      schema
    }),
    socialProviders: google,
    advanced: {
      cookiePrefix: "crossbeam_tw",
      useSecureCookies: config.APP_MODE !== "local",
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: "lax",
        secure: config.APP_MODE !== "local",
        path: "/"
      }
    },
    databaseHooks: {
      user: {
        create: {
          before: async (candidate) => isIdentityAllowed(config, appStore, candidate)
        }
      },
      session: {
        create: {
          // Re-checked at sign-in too, so an account that was allowlisted when it
          // was created cannot mint a fresh session after being revoked.
          before: async (candidate) => {
            const identity = await appStore.findAuthIdentity(candidate.userId);
            if (!identity) return false;
            return isIdentityAllowed(config, appStore, identity);
          }
        }
      }
    },
    plugins: [
      ...(config.APP_MODE === "local"
        ? [
            anonymous({
              disableDeleteAnonymousUser: true,
              generateName: () => "Private Pilot Owner",
              generateRandomEmail: () => `local-${randomUUID()}@local.invalid`
            })
          ]
        : []),
      nextCookies()
    ]
  });
}

let cachedAuth: ReturnType<typeof buildAuth> | undefined;

export function getAuth() {
  if (!cachedAuth) {
    const config = parseRuntimeConfig(process.env);
    if (config.APP_MODE === "production") {
      throw new Error("Production PostgreSQL auth adapter is not configured yet");
    }
    cachedAuth = buildAuth(config, getLocalDatabase(config), getAuthSecret(config));
  }
  return cachedAuth;
}
