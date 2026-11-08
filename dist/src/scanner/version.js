"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.packageVersion = packageVersion;
const node_fs_1 = require("node:fs");
const path = __importStar(require("node:path"));
const VERSION = process.env.npm_package_version ?? '1.0.0';
let cachedVersion = null;
/** Package version, resolved once from the nearest package.json. */
async function packageVersion() {
    if (cachedVersion)
        return cachedVersion;
    let dir = __dirname;
    for (let depth = 0; depth < 6; depth += 1) {
        try {
            const raw = await node_fs_1.promises.readFile(path.join(dir, 'package.json'), 'utf8');
            const parsed = JSON.parse(raw);
            // Match the scoped name *or* the legacy bare one, so an install made
            // before the package was published under `@vibefoundry/` still resolves
            // its own version instead of reporting the fallback.
            const isThisPackage = parsed.name === '@vibefoundry/vibe-shield' || parsed.name === 'vibe-shield';
            if (isThisPackage && parsed.version) {
                cachedVersion = parsed.version;
                return cachedVersion;
            }
        }
        catch {
            // Keep walking up.
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    cachedVersion = VERSION;
    return cachedVersion;
}
