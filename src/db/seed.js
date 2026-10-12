// One-time bootstrap: creates the first Super Administrator account.
//
// This exists ONLY to solve the chicken-and-egg problem created by the invite-only
// provisioning decision (confirmed by CPSRF leadership): every other user account is
// created via POST /api/v1/admin/users by an existing User-Manage-permitted admin -
// but the very first admin has to come from somewhere. Run this once, immediately
// after `npm run migrate`, against a fresh database. It refuses to run if a Super
// Administrator already exists, so it can't be used to mint a second one by accident.
//
// Usage:
//   SEED_SUPER_ADMIN_EMAIL=... SEED_SUPER_ADMIN_PASSWORD=... SEED_SUPER_ADMIN_NAME=... npm run seed
//
// The password you provide here is a real login credential, not a placeholder shown
// once - set it to something you'll actually use (or rotate immediately after first
// login), and don't leave it in shell history on a shared machine.

import { getPool, closePool } from './pool.js';
import { createUser } from '../auth/authService.js';
import { ROLES } from '../rbac/roles.js';

async function seed() {
  const email = process.env.SEED_SUPER_ADMIN_EMAIL;
  const password = process.env.SEED_SUPER_ADMIN_PASSWORD;
  const displayName = process.env.SEED_SUPER_ADMIN_NAME;

  if (!email || !password || !displayName) {
    console.error(
      'Missing required env vars. Set SEED_SUPER_ADMIN_EMAIL, SEED_SUPER_ADMIN_PASSWORD, ' +
      'and SEED_SUPER_ADMIN_NAME before running npm run seed.'
    );
    process.exitCode = 1;
    return;
  }

  const pool = getPool();
  const { rows } = await pool.query('SELECT id FROM users WHERE role = $1 LIMIT 1', [ROLES.SUPER_ADMINISTRATOR]);
  if (rows.length > 0) {
    console.log('A Super Administrator already exists - refusing to seed a second one. Use POST /api/v1/admin/users instead.');
    await closePool();
    return;
  }

  const user = await createUser({
    email,
    password,
    displayName,
    role: ROLES.SUPER_ADMINISTRATOR,
    actorId: null,
    actorRole: 'system.seed',
  });

  console.log(`Created first Super Administrator: ${user.email} (${user.id})`);
  console.log(
    'MFA is mandatory for this role - the next login will return status "mfa_setup_required" ' +
    'instead of a usable session until MFA enrollment is completed. This is expected.'
  );
  await closePool();
}

seed().catch(async (err) => {
  console.error('Seed failed:', err);
  process.exitCode = 1;
  await closePool();
});
