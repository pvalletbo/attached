import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const webDirectory = path.dirname(fileURLToPath(import.meta.url));
const assetsDirectory = path.join(webDirectory, "dist/assets");

for (const bindings of [
  "protocol-bindings",
  "sync-bindings",
  "iroh-bindings",
]) {
  const source = path.join(webDirectory, "src", bindings);
  const destination = path.join(assetsDirectory, bindings);
  mkdirSync(destination, { recursive: true });
  cpSync(source, destination, { recursive: true });
}
