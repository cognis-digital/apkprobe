#!/usr/bin/env node
import { run } from "./rules";

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  try {
    process.stdout.write(run(input) + "\n");
  } catch (e) {
    process.stderr.write("error: " + (e as Error).message + "\n");
    process.exit(1);
  }
});
