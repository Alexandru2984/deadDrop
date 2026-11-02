/**
 * Dead Drop — the first question, asked before the app arrives.
 *
 * Whether this browser is already signed in decides which page shows first,
 * and the app could only ask once all of its code had loaded: on a phone, a
 * round trip spent after everything else instead of during it. The page loads
 * this on its own, ahead of the app, so the answer is on its way while the
 * rest is. The app imports it too — the same module, run once — and takes
 * the answer the first time it asks; every later check asks afresh.
 */

let first = fetch('/api/me');
// Read later or never: a network error is the app's to handle, not the
// console's to report as unhandled.
first.catch(() => {});

/** The answer the page asked for on load, once; null after. */
export function firstAnswer() {
  const answer = first;
  first = null;
  return answer;
}
