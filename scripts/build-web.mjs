import { copyFile, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = join(root, "web");
const output = join(root, ".web-dist");
const staticFiles = [
  "_headers",
  ".well-known/apple-app-site-association",
  "icon-192.png",
  "icon-512.png",
  "icon.svg",
  "index.html",
  "manifest.webmanifest",
  "robots.txt",
  "styles.css",
  "sw.js",
  "third-party-notices.txt",
];

await rm(output, { recursive: true, force: true });
await mkdir(output);
await Promise.all(staticFiles.map(async (name) => {
  const destination = join(output, name);
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(join(source, name), destination);
}));
await build({
  entryPoints: [join(source, "app.js")],
  bundle: true,
  format: "esm",
  outfile: join(output, "app.js"),
  platform: "browser",
  target: "es2022",
  banner: {
    js: "/* QR Code Generator for JavaScript, Copyright (c) 2009 Kazuhiko Arase, MIT License. See /third-party-notices.txt */",
  },
});
