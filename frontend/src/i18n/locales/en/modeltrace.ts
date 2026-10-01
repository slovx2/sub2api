export default {
    description: 'Identify models returned by OpenAI OAuth accounts on a schedule. Probes do not change account state.',
    enabled: 'Enable probes', all: 'All accounts (including new accounts)', selected: 'Select accounts', selectAll: 'Select all current accounts', clear: 'Clear', search: 'Search accounts',
    interval: 'Interval (minutes, minimum 10)', concurrency: 'Concurrent accounts', request: 'Requested model', expected: 'Expected model (defaults to requested model)', add: 'Add model', remove: 'Remove',
    unknownModel: 'The expected model is not in the fingerprint bank and cannot be identified.', bank: 'Probabilities compare only the fingerprint candidates. Unlisted models may match an existing candidate.',
    save: 'Save probe settings', run: 'Probe now', saved: 'Probe settings saved', queued: 'Queued {accepted} accounts; {running} running or queued; {unavailable} unavailable.',
    error: 'Operation failed', loading: 'Loading…', dirty: 'Save settings before probing.', disabled: 'Disabled', running: 'Probing', matched: 'Matched', mismatched: 'Mismatched',
    pending: 'Pending', uncertain: 'Uncertain', failed: 'Undetermined', actual: 'Upstream request', retry: 'Retry', empty: 'No eligible accounts', enabledProtocol: 'Enable {protocol}',
}
