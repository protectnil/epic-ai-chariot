/**
 * Client security epoch — the mandated-patch-level floor this BUILD satisfies.
 *
 * A license JWT carries `min_security_epoch` (chariot-billing-service §5.1 /
 * CHARIOT-SPEC "Catalog floor"): the minimum client patch level the entitlement
 * requires. A client MAY run a license only when
 *   license.min_security_epoch <= CLIENT_SECURITY_EPOCH
 * i.e. this build is patched to at least the level the license mandates.
 *
 * This is the client-side comparand that makes `min_security_epoch` a real
 * kill-switch instead of an inert claim. BUMP this constant (and reissue
 * licenses with the matching `min_security_epoch`) whenever a mandatory
 * security patch ships that must be able to fence out unpatched clients.
 *
 * Monotonic: only ever increase this value. Lowering it would let an older,
 * unpatched build satisfy a floor it should not.
 */
export const CLIENT_SECURITY_EPOCH = 1;
