export function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

export async function settle(rounds = 6) {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}
