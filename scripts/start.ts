import { execSync } from 'child_process';
import * as fs from 'fs';

interface NsecbunkerConfig {
    nostr?: {
        relays?: string[];
    };
    admin?: {
        adminRelays?: string[];
    };
}

try {
    // Ensure config folder exists at the absolute path used by DATABASE_URL
    const configPath = '/app/config';
    if (!fs.existsSync(configPath)) {
        execSync(`mkdir -p ${configPath}`);
    }

    // Database paths
    const dbPath = `${configPath}/nsecbunker.db`;
    const templatePath = '/app/prisma/template.db';

    // Check if we should use pre-baked template or run migrations
    if (!fs.existsSync(dbPath) && fs.existsSync(templatePath)) {
        // Fast path: Use pre-baked template (testing with tmpfs)
        fs.copyFileSync(templatePath, dbPath);
    }
} catch (error: unknown) {
    // Log fatal error to stderr
    const err = error as { message?: string; stderr?: Buffer; stdout?: Buffer };
    console.error(`[MIGRATION] Error: ${err.message || error}`);
    process.exit(1);
}

const args = process.argv.slice(2);
const configArgIndex = args.indexOf('--config');
let runtimeConfigArg: string | null = configArgIndex !== -1 ? args[configArgIndex + 1] : null;

// nsecbunker modifies its config file at runtime, so we need to copy it to
// a writable location (tmpfs in testing) and optionally apply RELAYS override
if (runtimeConfigArg && fs.existsSync(runtimeConfigArg)) {
    try {
        const configContent = fs.readFileSync(runtimeConfigArg, 'utf-8');
        const config: NsecbunkerConfig = JSON.parse(configContent);

        // Apply RELAYS env override if set
        const relays = process.env.RELAYS;
        if (relays) {
            const relayList = relays.split(',').map((r) => r.trim());
            config.nostr = config.nostr || {};
            config.nostr.relays = relayList;
            config.admin = config.admin || {};
            config.admin.adminRelays = relayList;
        }

        // Write to runtime location (tmpfs in testing, ./config in dev)
        const runtimeConfigPath = '/app/config/nsecbunker-runtime.json';
        fs.writeFileSync(runtimeConfigPath, JSON.stringify(config, null, 2));

        // Update args to use runtime config
        args[configArgIndex + 1] = runtimeConfigPath;
    } catch (e: unknown) {
        const err = e as { message?: string };
        console.error(`Failed to prepare runtime config: ${err.message}`);
        // Continue with original config path (will fail if read-only)
    }
}
// Link process.argv[1] to the actual dist file (relative to CWD /app)
// This is used by yargs to determine the script name
process.argv = [process.execPath, './dist/index.js', ...args];

// Load the application directly in-process.
// ESM import relative to THIS file (/app/scripts/start.ts)
await import('../dist/index.js');
