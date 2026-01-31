import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Global ignores
  {
    ignores: ['dist/', 'node_modules/', 'dashboard/', 'hooks/', '*.ts', '*.mjs'],
  },

  // Base recommended rules
  ...tseslint.configs.recommended,

  // TypeScript source files
  {
    files: ['src/**/*.ts'],
    rules: {
      'no-console': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },

  // Test files -- relax rules
  {
    files: ['src/**/*.test.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },

  // CLI scripts -- console is expected
  {
    files: [
      'src/migrate.ts',
      'src/rebuild-index.ts',
      'src/verify-production.ts',
      'src/instrumentation.ts',
      'src/server.ts',
      'src/http-server.ts',
    ],
    rules: {
      'no-console': 'off',
    },
  },
);
