'use strict';

const assert = require('assert').strict;
const { describe, it } = require('mocha');
const packageLock = require('../package-lock.json');
const packageJson = require('../package.json');

const SUPPORTED_GLOB_VERSION = '13.0.6';

describe('Dependency overrides', function () {
  it('keeps every transitive glob dependency on the supported release', function () {
    assert.strictEqual(packageJson.overrides?.glob, SUPPORTED_GLOB_VERSION);

    const installedGlobVersions = new Set(
      Object.entries(packageLock.packages)
        .filter(([location]) => /(^|\/)node_modules\/glob$/.test(location))
        .map(([, dependency]) => dependency.version),
    );

    assert.deepStrictEqual([...installedGlobVersions], [SUPPORTED_GLOB_VERSION]);
  });
});
