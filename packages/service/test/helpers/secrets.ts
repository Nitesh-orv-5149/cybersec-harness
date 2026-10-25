import fs from 'node:fs';
import path from 'node:path';

// Fake credentials assembled at runtime so no credential-shaped literal exists in the repository.
export const FAKE = {
  stripe: ['sk', 'live', '4eC39HqLyjWDarjtT1zdp7dc'].join('_'),
  github: 'ghp' + '_' + 'R2d2C3poJk8sLm4nO6pQ8rS0tU2vW4xY6zA8',
};
export function writeLeakyProject(root: string) {
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src/config.js'), `// fixture\nconst stripe = "${FAKE.stripe}";\nconst token = "${FAKE.github}";\nmodule.exports = { stripe, token };\n`);
  fs.writeFileSync(path.join(root, 'dist/bundle.js'), `var t="${FAKE.github}";\n`);
}
