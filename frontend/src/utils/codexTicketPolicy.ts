export interface CodexTicketPolicy {
  ttl_seconds: number
  refresh_before_seconds: number
  max_attempts: number
  failure_cooldown_seconds: number
}

export function validCodexTicketPolicy(value: CodexTicketPolicy): boolean {
  return Number.isInteger(value.ttl_seconds) && value.ttl_seconds >= 60 && value.ttl_seconds <= 86400
    && Number.isInteger(value.refresh_before_seconds) && value.refresh_before_seconds >= 0 && value.refresh_before_seconds < value.ttl_seconds
    && Number.isInteger(value.max_attempts) && value.max_attempts >= 1 && value.max_attempts <= 10
    && Number.isInteger(value.failure_cooldown_seconds) && value.failure_cooldown_seconds >= 60 && value.failure_cooldown_seconds <= 86400
}
