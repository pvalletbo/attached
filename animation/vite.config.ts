import {defineConfig} from 'vite';
import motionCanvas from '@motion-canvas/vite-plugin';
import ffmpeg from '@motion-canvas/ffmpeg';

export default defineConfig({
  // The editor/export bridge is a local authoring tool, not a public web service.
  server: {host: '127.0.0.1'},
  plugins: [
    motionCanvas(),
    ffmpeg(),
  ],
});
