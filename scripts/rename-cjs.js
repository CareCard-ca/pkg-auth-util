import fs from 'fs';
import path from 'path';

const dir = './dist/cjs';

for (const file of fs.readdirSync(dir)) {
    if (file.endsWith('.js')) {
        fs.renameSync(
            path.join(dir, file),
            path.join(dir, file.replace('.js', '.cjs'))
        );
    }
}
