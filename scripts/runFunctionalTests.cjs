'use strict';

const { runIndexedMochaTests } = require('./testParallel/runIndexedMochaTests.cjs');

const parallelTestFiles = [
  'test/indexExports.test.js',
  'test/jwtUtilAuth.test.js',
  'test/keyGen.test.js',
  'test/pwdUtilAuth.test.js',
  'test/stringUtilAuth.test.js',
];

if (require.main === module) {
  runIndexedMochaTests(parallelTestFiles)
    .then(exitCode => {
      process.exitCode = exitCode;
    })
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    });
}

module.exports = { parallelTestFiles };
