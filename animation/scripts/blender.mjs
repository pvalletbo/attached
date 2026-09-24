// npm run blender recreates the editable .blend, 90 PNG frames, and embedded MP4.
// Blender + FFmpeg must be installed. BLENDER and FFMPEG can override executables.
import {spawnSync} from 'node:child_process';
import {mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

process.chdir(fileURLToPath(new URL('..', import.meta.url)));
const args = process.argv.slice(2);
if (args.length > 1 || (args.length && !['--check', '--still'].includes(args[0]))) {
  throw new Error('Usage: npm run blender [-- --check|--still]');
}
const blender = process.env.BLENDER ?? (process.platform === 'darwin'
  ? '/Applications/Blender.app/Contents/MacOS/Blender' : 'blender');
function run(command, args) {
  const result = spawnSync(command, args, {stdio: 'inherit'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.signal ?? result.status}).`);
}
run(blender, ['--background', '--factory-startup', '-t', '4', '--python', 'blender/padlock.py', '--', ...args]);
if (!args.length) {
  mkdirSync('src/assets', {recursive: true});
  run(process.env.FFMPEG ?? 'ffmpeg', [
    '-hide_banner', '-loglevel', 'error', '-y',
    '-f', 'lavfi', '-i', 'color=c=0x20201e:s=512x512:r=30',
    '-framerate', '30', '-i', 'output/blender/padlock-%04d.png',
    '-filter_complex', '[0:v][1:v]overlay=shortest=1:format=auto,format=yuv420p',
    '-an', '-c:v', 'libx264', '-crf', '20', '-g', '30', '-movflags', '+faststart',
    'src/assets/blender-padlock.mp4',
  ]);
  console.log(`Embedded clip: ${resolve('src/assets/blender-padlock.mp4')}`);
}
