import { ShieldCheck } from "lucide-react";

import styles from "./marketing.module.css";

export function Brand() {
  return (
    <span className={styles.brandLockup}>
      <span className={styles.brandSymbol} aria-hidden="true">
        <span className={styles.brandCore} />
        <ShieldCheck size={19} strokeWidth={1.9} />
      </span>
      <span className={styles.wordmark}>Hallu Defense</span>
    </span>
  );
}
