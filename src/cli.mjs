#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { requestAuthorization, EXIT } from './client.mjs';

// Never echo arguments, configuration, credentials or raw transport errors.
try {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('a2h request --summary "ação exata" [--ttl 300]');
  } else {
    if (args.shift() !== 'request') throw new Error('invalid_request');
    const options = {};
    while (args.length) {
      const key = args.shift();
      if (!['--summary', '--ttl'].includes(key) || Object.hasOwn(options, key) || !args.length) throw new Error('invalid_request');
      options[key] = args.shift();
    }
    const config = JSON.parse((await readFile(join(homedir(), '.h2a', 'config.json'), 'utf8')).replace(/^\uFEFF/, ''));
    const result = await requestAuthorization(config, { summary: options['--summary'],
      ttl: options['--ttl'] === undefined ? 300 : Number(options['--ttl']), token: process.env.A2H_API_KEY });
    console.log(JSON.stringify({ ...result, verified: result.decision !== 'expired' }));
    process.exitCode = EXIT[result.decision];
  }
} catch (error) {
  const invalid = ['invalid_decision', 'invalid_signature'].includes(error?.message);
  console.error(JSON.stringify({ decision: 'denied', error: invalid ? 'verification_failed' : 'request_failed' }));
  process.exitCode = invalid ? EXIT.invalid : EXIT.error;
}
