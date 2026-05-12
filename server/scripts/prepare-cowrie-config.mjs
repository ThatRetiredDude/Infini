#!/usr/bin/env node
/* global console, process */
/**
 * Ensures COWRIE_HOME layout and seeds cowrie.cfg from Cowrie's cowrie.cfg.dist.
 * Optional: enable Telnet via COWRIE_TELNET_ENABLED=1 (patches [telnet] enabled).
 */
import fs from 'node:fs';
import path from 'node:path';

const home = process.env.COWRIE_HOME || '/data/cowrie';
const installDir = process.env.COWRIE_INSTALL_DIR || '/opt/cowrie-install';
const distPath = path.join(installDir, 'etc', 'cowrie.cfg.dist');
const cfgPath = path.join(home, 'etc', 'cowrie.cfg');

function patchTelnetEnabled(text) {
  const lines = text.split(/\n/);
  let inTelnet = false;
  const out = [];
  let patched = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\[telnet\]\s*$/.test(line)) {
      inTelnet = true;
      out.push(line);
      continue;
    }
    if (/^\[/.test(line) && !/^\[telnet\]\s*$/.test(line)) {
      inTelnet = false;
    }
    if (inTelnet && /^enabled\s*=\s*false\s*$/i.test(line) && !patched) {
      out.push('enabled = true');
      patched = true;
      continue;
    }
    out.push(line);
  }
  return out.join('\n');
}

function main() {
  fs.mkdirSync(path.join(home, 'var', 'log', 'cowrie'), { recursive: true });
  fs.mkdirSync(path.join(home, 'var', 'lib', 'cowrie'), { recursive: true });
  fs.mkdirSync(path.join(home, 'etc'), { recursive: true });

  if (!fs.existsSync(cfgPath)) {
    if (fs.existsSync(distPath)) {
      fs.copyFileSync(distPath, cfgPath);
      console.warn('[prepare-cowrie] seeded cowrie.cfg from cowrie.cfg.dist');
    } else {
      console.warn('[prepare-cowrie] cowrie.cfg.dist not found at', distPath);
      return;
    }
  }

  if (process.env.COWRIE_TELNET_ENABLED === '1') {
    let s = fs.readFileSync(cfgPath, 'utf8');
    s = patchTelnetEnabled(s);
    fs.writeFileSync(cfgPath, s);
  }
}

main();
