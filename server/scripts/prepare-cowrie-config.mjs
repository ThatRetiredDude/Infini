#!/usr/bin/env node
/* global console, process */
/**
 * Ensures COWRIE_HOME layout and seeds cowrie.cfg from Cowrie's cowrie.cfg.dist.
 * Telnet is enabled by default for the interactive network honeypot.
 * Set COWRIE_TELNET_ENABLED=0 to leave Cowrie's stock Telnet setting disabled.
 * Cowrie's launcher resolves etc/cowrie.cfg relative to its install directory,
 * so this also links that path back to the persisted COWRIE_HOME config.
 */
import fs from 'node:fs';
import path from 'node:path';

const home = process.env.COWRIE_HOME || '/data/cowrie';
const installDir = process.env.COWRIE_INSTALL_DIR || '/opt/cowrie-install';
const distPath = path.join(installDir, 'etc', 'cowrie.cfg.dist');
const installCfgPath = path.join(installDir, 'etc', 'cowrie.cfg');
const cfgPath = path.join(home, 'etc', 'cowrie.cfg');

function upsertSectionValue(text, sectionName, key, value) {
  const lines = text.split(/\n/);
  const sectionRe = new RegExp(`^\\[${sectionName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\]\\s*$`);
  const anySectionRe = /^\[[^\]]+\]\s*$/;
  const keyRe = new RegExp(`^\\s*#?\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=`, 'i');
  const out = [];
  let patched = false;
  let inSection = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (sectionRe.test(line)) {
      inSection = true;
      out.push(line);
      continue;
    }

    if (inSection && anySectionRe.test(line)) {
      if (!patched) {
        out.push(`${key} = ${value}`);
        patched = true;
      }
      inSection = false;
    }

    if (inSection && keyRe.test(line) && !patched) {
      out.push(`${key} = ${value}`);
      patched = true;
      continue;
    }

    out.push(line);
  }

  if (inSection && !patched) {
    out.push(`${key} = ${value}`);
    patched = true;
  }

  if (!patched) {
    if (out.length && out[out.length - 1] !== '') out.push('');
    out.push(`[${sectionName}]`);
    out.push(`${key} = ${value}`);
  }

  return out.join('\n');
}

function patchCowrieConfig(text) {
  let patched = text;
  const hostname = process.env.COWRIE_HOSTNAME || 'prd-bastion-01';
  patched = upsertSectionValue(patched, 'honeypot', 'hostname', hostname);
  patched = upsertSectionValue(patched, 'honeypot', 'log_path', path.join(home, 'var', 'log', 'cowrie'));
  patched = upsertSectionValue(patched, 'honeypot', 'state_path', path.join(home, 'var', 'lib', 'cowrie'));
  patched = upsertSectionValue(patched, 'honeypot', 'download_path', `${path.join(home, 'var', 'lib', 'cowrie')}/downloads`);
  patched = upsertSectionValue(patched, 'honeypot', 'ttylog_path', `${path.join(home, 'var', 'lib', 'cowrie')}/tty`);
  patched = upsertSectionValue(patched, 'output_jsonlog', 'enabled', 'true');
  patched = upsertSectionValue(
    patched,
    'output_jsonlog',
    'logfile',
    process.env.COWRIE_JSON_LOG || path.join(home, 'var', 'log', 'cowrie', 'cowrie.json'),
  );

  if (process.env.COWRIE_TELNET_ENABLED !== '0') {
    patched = upsertSectionValue(patched, 'telnet', 'enabled', 'true');
  }

  return patched;
}

function linkInstallConfigToPersistedConfig() {
  try {
    if (fs.existsSync(installCfgPath)) {
      const st = fs.lstatSync(installCfgPath);
      if (st.isSymbolicLink() && fs.readlinkSync(installCfgPath) === cfgPath) return;
      fs.rmSync(installCfgPath, { force: true });
    }
    fs.symlinkSync(cfgPath, installCfgPath);
    console.warn('[prepare-cowrie] linked install cowrie.cfg to persisted COWRIE_HOME config');
  } catch (err) {
    console.warn('[prepare-cowrie] failed to link install cowrie.cfg:', err?.message || err);
  }
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

  const current = fs.readFileSync(cfgPath, 'utf8');
  const patched = patchCowrieConfig(current);
  if (patched !== current) {
    fs.writeFileSync(cfgPath, patched);
    console.warn('[prepare-cowrie] patched cowrie.cfg for persisted logs/state');
  }

  linkInstallConfigToPersistedConfig();
}

main();
