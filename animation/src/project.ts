import {makeProject} from '@motion-canvas/core';

import '@fontsource/inter/400.css';
import '@fontsource/inter/600.css';
import '@fontsource/jetbrains-mono/400.css';
import overview from './scenes/overview?scene';
import setup from './scenes/setup?scene';
import discovery from './scenes/discovery?scene';
import tunnel from './scenes/tunnel?scene';
import ssh from './scenes/ssh?scene';
import workflow from './scenes/workflow?scene';

export default makeProject({
  name: 'attached-explained',
  scenes: [overview, setup, discovery, tunnel, ssh, workflow],
});
