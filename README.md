# mapguard
mapguard is a CLI security tool that scans npm packages and published JavaScript/TypeScript bundles for accidentally included source map (.map) files that reference or embed original source code. Inspired by real-world incidents like Anthropic's accidental Claude Code source leak via a map file in their npm package, mapguard analyzes local director
