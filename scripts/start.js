const { execSync, spawn } = require('child_process');
const fs = require('fs');

try {
  console.log(`Running migrations`);
  // Ensure config folder exists at the absolute path used by DATABASE_URL
  const configPath = '/app/config';
  if (!fs.existsSync(configPath)) {
    execSync(`mkdir -p ${configPath}`);
  }
  console.log(`Generating Prisma Client...`);
  execSync('npx prisma generate', { stdio: 'inherit' });
  console.log(`Running migrations...`);
  execSync('npm run prisma:migrate', { stdio: 'inherit' });
  console.log(`Migrations finished.`);
} catch (error) {
  console.log('Startup error:', error);
  // Handle any potential migration errors here
}

const args = process.argv.slice(2);
const configArgIndex = args.indexOf('--config');
let configPath = configArgIndex !== -1 ? args[configArgIndex + 1] : null;

// nsecbunker modifies its config file at runtime, so we need to copy it to
// a writable location (tmpfs in testing) and optionally apply RELAYS override
if (configPath && fs.existsSync(configPath)) {
  try {
    const configContent = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(configContent);

    // Apply RELAYS env override if set
    const relays = process.env.RELAYS;
    if (relays) {
      const relayList = relays.split(',').map(r => r.trim());
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
  } catch (e) {
    console.error(`Failed to prepare runtime config: ${e.message}`);
    // Continue with original config path (will fail if read-only)
  }
}

const childProcess = spawn('node', ['./dist/index.js', ...args], {
  stdio: 'inherit',
});

childProcess.on('exit', (code) => {
  process.exit(code);
});
