// @ts-check

// Based on The Digital Stride's payload-starter. eslint-config-next 16 ships native flat configs:
// do not load them through @eslint/eslintrc FlatCompat, whose validator crashes on their circular
// refs.
import nextCoreWebVitals from 'eslint-config-next/core-web-vitals'
import nextTypescript from 'eslint-config-next/typescript'
import reactHooks from 'eslint-plugin-react-hooks'

const eslintConfig = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      // A plugin has no pages/ directory; the dev app uses the App Router.
      '@next/next/no-html-link-for-pages': 'off',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { fixStyle: 'separate-type-imports' },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'after-used',
          argsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^(_|ignore)',
          destructuredArrayIgnorePattern: '^_',
          ignoreRestSiblings: false,
          vars: 'all',
          varsIgnorePattern: '^_',
        },
      ],
    },
  },
  {
    ignores: [
      '**/.next/',
      '**/dist/',
      '**/node_modules/',
      '**/payload-types.ts',
      '**/*.generated.ts',
      'dev/app/(payload)/**',
      // Written by `payload migrate:create`; regenerated, never edited by hand.
      'dev/migrations/**',
      'test/.tmp/**',
      'test-results/',
      'playwright-report/',
      '.claude/worktrees/**',
    ],
  },
]

export default eslintConfig
