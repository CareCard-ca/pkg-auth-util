import { defineConfig, globalIgnores } from 'eslint/config';

const eslintConfig = defineConfig([
  globalIgnores([
    // Default ignores of eslint-config-next:
    "out/**",
    "build/**",
    "dist/**",
    "coverage/**",
    "node_modules/**",
  ]),
]);

export default eslintConfig;
