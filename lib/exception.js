export class BlockedError extends Error {
  constructor() {
    super(...arguments);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, BlockedError);
    }

    this.name = this.constructor.name;
  }
}
