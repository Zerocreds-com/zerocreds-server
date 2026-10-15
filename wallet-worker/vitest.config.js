import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';

export default defineConfig(async () => ({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: { bindings: { MIGRATIONS: await readD1Migrations('./migrations') } },
  })],
  test: { setupFiles: ['./test/setup.js'], include: ['test/*.test.js'], fileParallelism: false },
}));
