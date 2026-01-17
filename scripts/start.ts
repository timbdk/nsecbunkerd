import { execSync, spawn, type ChildProcess } from 'child_process';
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
    console.log(`[SIGNER] Starting...`);

    // Ensure config folder exists at the absolute path used by DATABASE_URL
    const configPath = '/app/config';
    if (!fs.existsSync(configPath)) {
        console.log(`[SIGNER] Creating config directory: ${configPath}`);
        execSync(`mkdir -p ${configPath}`);
    }

    // Database paths
    const dbPath = `${configPath}/nsecbunker.db`;
    const templatePath = '/app/prisma/template.db';

    // Check if we should use pre-baked template or run migrations
    if (!fs.existsSync(dbPath) && fs.existsSync(templatePath)) {
        // Fast path: Use pre-baked template (testing with tmpfs)
        console.log(`[SIGNER] Using pre-baked database template`);
        fs.copyFileSync(templatePath, dbPath);
        console.log(`[SIGNER] ✅ Database ready (from template)`);
    } else {
        // Normal path: Run migrations (dev/prod with persistent volumes)
        // Note: Prisma Client is pre-generated at Docker build time (see Dockerfile)
        console.log(`[SIGNER:MIGRATION] Running migrations...`);
        execSync('npm run prisma:migrate', { stdio: 'inherit' });
        console.log(`[SIGNER:MIGRATION] ✅ Migrations completed successfully`);
    }
} catch (error: unknown) {
    // Log detailed error information for debugging
    console.error(`[SIGNER:MIGRATION] ❌ MIGRATION FAILED`);
    console.error(`[SIGNER:MIGRATION] Timestamp: ${new Date().toISOString()}`);

    const err = error as { message?: string; stderr?: Buffer; stdout?: Buffer };
    console.error(`[SIGNER:MIGRATION] Error: ${err.message || error}`);
    if (err.stderr) {
        console.error(`[SIGNER:MIGRATION] stderr: ${err.stderr.toString()}`);
    }
    if (err.stdout) {
        console.error(`[SIGNER:MIGRATION] stdout: ${err.stdout.toString()}`);
    }
    console.error(`[SIGNER:MIGRATION] DATABASE_URL: ${process.env.DATABASE_URL || 'not set'}`);
    console.error(`[SIGNER:MIGRATION] Exiting due to migration failure`);
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
            console.log(`Applying RELAYS override: ${relayList.join(', ')}`);
            config.nostr = config.nostr || {};
            config.nostr.relays = relayList;
            config.admin = config.admin || {};
            config.admin.adminRelays = relayList;
        }

        // Write to runtime location (tmpfs in testing, ./config in dev)
        const runtimeConfigPath = '/app/config/nsecbunker-runtime.json';
        fs.writeFileSync(runtimeConfigPath, JSON.stringify(config, null, 2));
        console.log(`Runtime config written to ${runtimeConfigPath}`);

        // Update args to use runtime config
        args[configArgIndex + 1] = runtimeConfigPath;
    } catch (e: unknown) {
        const err = e as { message?: string };
        console.error(`Failed to prepare runtime config: ${err.message}`);
        // Continue with original config path (will fail if read-only)
    }
}

const childProcess: ChildProcess = spawn('node', ['./dist/index.js', ...args], {
    stdio: 'inherit',
});

childProcess.on('exit', (code: number | null) => {
    process.exit(code ?? 1);
});
