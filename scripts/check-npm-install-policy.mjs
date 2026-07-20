import { readFile } from "node:fs/promises";
import path from "node:path";

const projectDirectories = process.argv.slice(2);

if (projectDirectories.length === 0) {
  console.error("usage: node check-npm-install-policy.mjs <project-directory> [...]");
  process.exit(2);
}

function packageNameFromLocation(location) {
  const marker = "node_modules/";
  const markerIndex = location.lastIndexOf(marker);
  if (markerIndex === -1) return null;

  const tail = location.slice(markerIndex + marker.length);
  const parts = tail.split("/");
  return tail.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function parsePinnedKey(key) {
  const separator = key.startsWith("@")
    ? key.indexOf("@", key.indexOf("/") + 1)
    : key.lastIndexOf("@");

  if (separator <= 0 || separator === key.length - 1) return null;
  return { name: key.slice(0, separator), version: key.slice(separator + 1) };
}

let failed = false;

for (const directory of projectDirectories) {
  const projectDirectory = path.resolve(directory);
  const manifestPath = path.join(projectDirectory, "package.json");
  const lockfilePath = path.join(projectDirectory, "package-lock.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const lockfile = JSON.parse(await readFile(lockfilePath, "utf8"));
  const errors = [];

  const policy = manifest.allowScripts;
  if (!policy || Array.isArray(policy) || typeof policy !== "object") {
    errors.push("allowScripts must be an object");
  }

  const scriptPackages = new Map();
  for (const [location, metadata] of Object.entries(lockfile.packages ?? {})) {
    if (!location || metadata.hasInstallScript !== true) continue;

    const name = packageNameFromLocation(location);
    if (!name || typeof metadata.version !== "string") {
      errors.push(`cannot identify script-bearing lockfile entry ${location}`);
      continue;
    }

    if (!scriptPackages.has(name)) scriptPackages.set(name, new Set());
    scriptPackages.get(name).add(metadata.version);
  }

  if (policy && !Array.isArray(policy) && typeof policy === "object") {
    for (const [key, value] of Object.entries(policy)) {
      const pin = parsePinnedKey(key);

      if (typeof value !== "boolean") {
        errors.push(`${key} must be true or false`);
        continue;
      }

      if (value === true) {
        if (!pin) {
          errors.push(`${key}: name-wide true approvals are forbidden`);
        } else if (!scriptPackages.get(pin.name)?.has(pin.version)) {
          errors.push(`${key}: approval does not match a locked install script`);
        }
      } else if (pin) {
        errors.push(`${key}: denials must use the package name without a version`);
      } else if (!scriptPackages.has(key)) {
        errors.push(`${key}: denial does not match a locked install script`);
      }
    }

    for (const [name, versions] of scriptPackages) {
      for (const version of versions) {
        if (policy[name] === false || policy[`${name}@${version}`] === true) continue;
        errors.push(`${name}@${version}: install script is not denied or exactly approved`);
      }
    }
  }

  const label = path.relative(process.cwd(), projectDirectory) || ".";
  if (errors.length > 0) {
    failed = true;
    for (const error of errors) console.error(`${label}: ${error}`);
  } else {
    const identityCount = [...scriptPackages.values()].reduce(
      (total, versions) => total + versions.size,
      0,
    );
    console.log(
      `${label}: npm install-script policy covers ${identityCount} locked package version(s)`,
    );
  }
}

if (failed) process.exit(1);
