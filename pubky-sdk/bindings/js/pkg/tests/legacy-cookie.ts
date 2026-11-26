import { AuthFlowKind, Pubky as LegacyPubky } from "pubky-legacy/index.js";
import type { Pubky, PublicKey, Session, Signer } from "../index.js";

// Start with a cookie issued to the last SDK release that requested them.
export async function restoreLegacyCookie(
  sdk: Pubky,
  signer: Signer,
  homeserver: PublicKey,
  signupToken: string,
): Promise<Session> {
  await signer.signup(homeserver, signupToken);
  const flow = LegacyPubky.testnet().startCookieAuthFlow(
    "/:rw", AuthFlowKind.signin(), "http://localhost:15412/inbox",
  );
  await signer.approveAuthRequest(flow.authorizationUrl);
  const session = await flow.awaitApproval();
  const exported = typeof window === "undefined"
    ? await session.cookie!.exportSecret()
    : session.export();
  return sdk.restoreSession(exported);
}
