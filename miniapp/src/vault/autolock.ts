/**
 * Auto-lock by inactivity (BRIEF §6.3, default 60s). On lock we zero the user
 * key in memory and drop the access token. The master password is required to
 * bootstrap again after a full lock.
 */
import { wipe } from "../crypto/primitives";
import type { SymmetricKey } from "../crypto/encstring";
import { stopAllActiveReveals } from "../reveal/engine";

export class AutoLock {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private userKey: SymmetricKey | null = null;

  constructor(
    private readonly timeoutMs: number,
    private readonly onLock: () => void,
  ) {}

  hold(userKey: SymmetricKey): void {
    this.userKey = userKey;
    this.touch();
  }

  /** Reset the inactivity timer (call on user interaction). */
  touch(): void {
    if (!this.userKey) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.lock(), this.timeoutMs);
  }

  lock(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    // Any secret currently on screen must disappear the instant we lock —
    // the reveal engine tracks in-progress reveals precisely for this call.
    stopAllActiveReveals();
    if (this.userKey) {
      wipe(this.userKey.encKey, this.userKey.macKey);
      this.userKey = null;
    }
    this.onLock();
  }

  get locked(): boolean {
    return this.userKey === null;
  }
}
