import { applyD1Migrations, env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.MIGRATIONS);
  await applyD1Migrations(env.VAULT_DB, env.VAULT_MIGRATIONS);
});
