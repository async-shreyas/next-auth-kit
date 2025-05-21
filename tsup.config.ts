import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/providers/oauth.ts',
    'src/components/auth-ui.tsx',
    'src/hooks/use-auth.tsx',
    'src/server/auth.ts',
    'src/middleware/auth-middleware.ts',
  ],
  format: ['cjs', 'esm'],
  splitting: false,
  sourcemap: true,
  clean: true,
  dts: true,
  treeshake: true,
  minify: true,
  external: [
    'react',
    'react-dom',
    'next',
    'next/navigation',
    'next/server',
    'next/headers',
  ],
  // Ignore resolution errors for lib/prisma
  // This tells tsup not to worry about resolving this import
  // as it's considered external and will be handled by the user
  noExternal: [],
  esbuildOptions(options) {
    options.banner = {
      js: '/**\n * Next Auth Kit\n * A comprehensive authentication solution for Next.js\n * https://github.com/username/next-auth-kit\n */',
    };
  },
});