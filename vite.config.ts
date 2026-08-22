import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-masked-core/
export default defineConfig({
  base: '/crypto-lab-masked-core/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest specs
    // and get collected as empty suites if they are not excluded here.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
