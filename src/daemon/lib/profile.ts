import NDK, { NDKEvent, NDKPrivateKeySigner, type NostrEvent, type NDKUserProfile } from "@nostr-dev-kit/ndk";
import crypto from 'crypto';
import createDebug from "debug";

const debug = createDebug("nsecbunker:profile");

/**
 * Setup a skeleton profile for a new key since
 * the experience of a completely empty profile
 * is pretty bad when logging in with Coracle.
 *
 * @param key - The private key signer for the new user
 * @param profile - Optional profile data to use
 * @param email - if provided, will fetch the gravatar
 * @param explicitRelayUrls - Required: the relays to publish profile events to
 */
export async function setupSkeletonProfile(key: NDKPrivateKeySigner, profile: NDKUserProfile | undefined, email: string | undefined, explicitRelayUrls: string[]) {
    if (!explicitRelayUrls || explicitRelayUrls.length === 0) {
        debug('No relay URLs provided, skipping skeleton profile setup');
        return;
    }
    const rand = Math.random().toString(36).substring(7);
    profile ??= {};
    profile.display_name ??= 'New User via nsecBunker';
    profile.about ??= 'This is a skeleton profile. You should edit it.';
    profile.website ??= 'https://nsecbunker.com';
    profile.image ??= `https://robohash.org/${rand}?set=set5`;

    if (email) {
        try {
            const trimmedEmail = email.trim().toLowerCase();
            const hash = crypto.createHash('md5').update(trimmedEmail).digest('hex');
            profile.image = `https://robohash.org/${hash}?gravatar=hashed&set=set5`;
            debug('fetching gravatar', profile.image);
        } catch (e) {
            debug('error fetching gravatar', e);
        }
    }

    const user = await key.user();
    const ndk = new NDK({
        explicitRelayUrls,
        signer: key
    });

    await ndk.connect(5000);
    user.ndk = ndk;

    try {
        let event = new NDKEvent(ndk, {
            kind: 0,
            content: JSON.stringify(profile),
            pubkey: user.pubkey,
        } as NostrEvent);
        await event.sign(key);

        const t = await event.publish();
        debug(`Published to ${t.size} relays`);

        event = new NDKEvent(ndk, {
            kind: 3,
            tags: [
                ['p', 'fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52'],
                ['p', user.pubkey],
            ],
            pubkey: user.pubkey,
        } as NostrEvent);
        await event.sign(key);
        debug(`follow list event`, event.rawEvent());
        await event.publish();

        const relays = new NDKEvent(ndk, {
            kind: 10002,
            tags: explicitRelayUrls.map(url => ['r', url]),
            pubkey: user.pubkey,
        } as NostrEvent);
        await relays.sign(key);
        await relays.publish();
    } finally {
        if (ndk.pool) {
            ndk.pool.relays.forEach(relay => relay.disconnect());
        }
    }
}
