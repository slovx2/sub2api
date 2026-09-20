export interface CodexTicketPolicy {
  ttl_seconds: number
  refresh_before_seconds: number
  max_consecutive_failures: number
  harvest_interval_seconds: number
}

export function validCodexTicketPolicy(value: CodexTicketPolicy): boolean {
  return Number.isInteger(value.ttl_seconds) && value.ttl_seconds >= 60 && value.ttl_seconds <= 86400
    && Number.isInteger(value.refresh_before_seconds) && value.refresh_before_seconds >= 0 && value.refresh_before_seconds < value.ttl_seconds
    && Number.isInteger(value.max_consecutive_failures) && value.max_consecutive_failures >= 1 && value.max_consecutive_failures <= 10000
    && Number.isInteger(value.harvest_interval_seconds) && value.harvest_interval_seconds >= 1 && value.harvest_interval_seconds <= 86400
}
