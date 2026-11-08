/** Best-effort removal of recognized credentials from report text. */
import { findSecrets } from '../secrets/patterns';

export function redactReportText(text: string): string {
  let output = text;
  for (const match of findSecrets(text)) {
    output = output.split(match.value).join(match.display);
  }
  return output;
}
