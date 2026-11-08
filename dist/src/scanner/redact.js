"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redactReportText = redactReportText;
/** Best-effort removal of recognized credentials from report text. */
const patterns_1 = require("../secrets/patterns");
function redactReportText(text) {
    let output = text;
    for (const match of (0, patterns_1.findSecrets)(text)) {
        output = output.split(match.value).join(match.display);
    }
    return output;
}
