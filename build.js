import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['./node_modules/@noble/post-quantum/ml-kem.js'],
  bundle: true,
  format: 'esm',
  outfile: './lib/ml-kem-bundle.js',
  platform: 'browser',
  target: 'es2020',
  minify: false,
  sourcemap: true,
  define: {
    'process.env.NODE_DEBUG': 'undefined'
  }
});

console.log('Bundle created: lib/ml-kem-bundle.js');
