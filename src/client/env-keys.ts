// The client-flip env-key derivation, in one place.
//
// This lives in its own leaf module for the same reason `src/env-token.ts`
// does: the credential provider chain, the transport resolver, and the
// conformance rule that polices the seam all need the SAME key names, and a
// second spelling of them is a second thing that can drift. The conformance
// rule in particular is only sound because it asks this function what the
// seam's key names are rather than approximating them with a pattern.

import { envToken } from "../env-token.js";

export interface ClientTransportEnvKeys {
  /** Mode keys, in precedence order. */
  modeKeys: string[];
  /** API base-URL keys, in precedence order. */
  apiUrlKeys: string[];
  /** API-key keys, in precedence order. */
  apiKeyKeys: string[];
}

/** Resolve the canonical client-flip env-key spec for an app. */
export function clientTransportEnvKeys(name: string): ClientTransportEnvKeys {
  const envSegment = envToken(name);
  return {
    modeKeys: [
      `HASNA_${envSegment}_STORAGE_MODE`,
      `HASNA_${envSegment}_MODE`,
      `${envSegment}_STORAGE_MODE`,
      `${envSegment}_MODE`,
    ],
    apiUrlKeys: [`HASNA_${envSegment}_API_URL`, `${envSegment}_API_URL`],
    apiKeyKeys: [`HASNA_${envSegment}_API_KEY`, `${envSegment}_API_KEY`],
  };
}

/**
 * The deliberate per-service override key.
 *
 * The whole point of this variable is that NOTHING populates it automatically.
 * Shell init auto-exports the fleet credential files into every shell, which is
 * why the presence of `HASNA_<NAME>_API_KEY` carries no signal about intent —
 * unlike `AWS_ACCESS_KEY_ID`, which is only ever set on purpose. This name is
 * reserved for a human or a CI job that means it, so it is the one env tier
 * that may outrank the credential on disk.
 */
export function credentialOverrideEnvKey(name: string): string {
  return `HASNA_${envToken(name)}_API_KEY_OVERRIDE`;
}

/** The global profile pointer. Selects WHICH identity, never carries a secret. */
export const CREDENTIAL_PROFILE_ENV_KEY = "HASNA_PROFILE";
