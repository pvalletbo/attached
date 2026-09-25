import {makeProject} from '@motion-canvas/core';
import '@fontsource/anton/latin-400.css';
import '@fontsource/jetbrains-mono/latin-400.css';
import film from './zine/film?scene';

export default makeProject({
  name: 'attached-zine',
  scenes: [film],
});
