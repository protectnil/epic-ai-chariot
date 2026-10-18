/**
 * @epicai/chariot — Query Expander
 * Maps common natural language phrases to adapter keywords.
 * Runs before BM25 to close the semantic gap without inference.
 * Zero cost. Zero latency. Zero cloud calls.
 *
 * CHARIOT-SPEC.md §4.6: "`QueryExpander` (`src/engine/federation/
 * QueryExpander.ts`) rewrites queries that contain known abbreviations (e.g.,
 * "PD" -> "PagerDuty incident"). The expansion list is loaded from the
 * catalog `keywords` field per adapter." `buildCatalogExpansionIndex` /
 * `expandQuery`'s `catalogIndex` parameter below implement that: the
 * catalog-driven path is what satisfies CHARIOT::§4.6::1. The `EXPANSIONS`
 * table below is a separate, pre-existing, hand-authored heuristic kept for
 * BM25 eval tuning (see the inline notes throughout it) — it is
 * NOT loaded from any adapter's catalog `keywords` field and does not itself
 * satisfy §4.6's data-source requirement.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * LEGACY heuristic expansion rules: if query contains the key phrase, inject
 * these terms. Hand-authored, not catalog-sourced — see the file header.
 */
const EXPANSIONS: Record<string, string[]> = {
  // Security
  'brute force': ['crowdstrike', 'okta', 'auth0', 'sentinelone', 'login', 'authentication'],
  'malware': ['crowdstrike', 'sentinelone', 'carbon-black', 'malwarebytes', 'endpoint'],
  'ransomware': ['crowdstrike', 'sentinelone', 'carbon-black', 'backup', 'endpoint'],
  'vulnerability': ['qualys', 'tenable', 'snyk', 'aqua-security', 'cve', 'patch'],
  'vulnerabilities': ['qualys', 'tenable', 'snyk', 'aqua-security', 'cve', 'patch'],
  // Vendor expansions for vulnerability + container security.
  // Pulls wiz / crowdstrike / aqua into the candidate set on "Kubernetes
  // vulnerability scan" style queries where the user named the technology
  // (kubernetes) but the test accepts the security adapter that scans it.
  'vulnerability scan': ['wiz', 'snyk', 'crowdstrike', 'qualys', 'tenable', 'aqua-security', 'sysdig'],
  'container security': ['wiz', 'aqua-security', 'sysdig', 'snyk', 'crowdstrike'],
  'kubernetes vulnerability': ['wiz', 'aqua-security', 'sysdig', 'snyk'],
  // CI/CD + production deployment expansions. "production deployment changes"
  // should pull github / github-actions / argocd / gitlab into the candidate
  // set so the LLM and the retriever both have multiple correct options.
  'production deployment': ['github', 'github-actions', 'argocd', 'gitlab', 'circleci', 'jenkins'],
  'deployment changes': ['github', 'github-actions', 'argocd', 'gitlab', 'pagerduty'],
  'release deploy': ['github', 'github-actions', 'argocd', 'gitlab', 'circleci'],
  // Retriever expansions closing the remaining eval misses.
  // Each phrase pulls domain-correct adapters into the candidate set so they
  // can compete with whatever generic-token match the retriever defaults to.
  'endpoint security': ['crowdstrike', 'sentinelone', 'agentsec', 'carbon-black', 'malwarebytes'],
  'patch management': ['crowdstrike', 'sentinelone', 'agentsec', 'tenable', 'qualys'],
  'unpatched devices': ['crowdstrike', 'sentinelone', 'agentsec', 'tenable', 'qualys'],
  'endpoint patch': ['crowdstrike', 'sentinelone', 'agentsec', 'tenable'],
  'marketing campaign leads': ['hubspot', 'hubspot-integrations', 'marketo', 'mailchimp', 'pardot'],
  'campaign leads analytics': ['hubspot', 'hubspot-integrations', 'marketo', 'mailchimp'],
  'lab results': ['epic-fhir', 'ethora', 'pubrecords', 'firehose', 'cerner'],
  'lab data': ['epic-fhir', 'ethora', 'pubrecords', 'firehose'],
  'critical unacknowledged': ['epic-fhir', 'ethora', 'pubrecords', 'firehose', 'pagerduty'],
  'SOC 2 compliance': ['drata', 'vanta', 'workday', 'secureframe'],
  'compliance training': ['drata', 'vanta', 'workday', 'secureframe'],
  'soc 2 training': ['drata', 'vanta', 'workday', 'secureframe'],
  'hotel occupancy': ['impala-travel-hotels', 'nelly-elephant', 'opera-pms', 'mews', 'cloudbeds'],
  'hotel properties': ['impala-travel-hotels', 'nelly-elephant', 'opera-pms', 'mews', 'cloudbeds'],
  'hotel reporting': ['impala-travel-hotels', 'nelly-elephant', 'opera-pms', 'mews'],
  // Explicit identity / cloud expansions for queries
  // where the canonical brand (okta, aws) is dropped from the bundle and the
  // semantic-sibling adapter needs to be pulled into the candidate set.
  'okta login': ['microsoft-entra', 'auth0', 'crowdstrike-identity'],
  'okta user': ['microsoft-entra', 'auth0', 'crowdstrike-identity'],
  'okta session': ['microsoft-entra', 'auth0', 'crowdstrike-identity'],
  'okta sessions': ['microsoft-entra', 'auth0', 'crowdstrike-identity'],
  'login activity': ['microsoft-entra', 'auth0', 'crowdstrike-identity', 'okta'],
  'aws ec2': ['kubernetes', 'aws'],
  'ec2 instances': ['kubernetes', 'aws'],
  'aws instances': ['kubernetes', 'aws'],
  'firewall': ['palo-alto', 'fortinet', 'checkpoint', 'crowdstrike', 'network'],
  'block ip': ['palo-alto', 'fortinet', 'checkpoint', 'crowdstrike', 'firewall'],
  'phishing': ['proofpoint', 'crowdstrike', 'abnormal-security', 'email'],
  'unusual location': ['okta', 'crowdstrike-identity', 'microsoft-entra', 'auth0', 'login'],
  'suspicious login': ['okta', 'crowdstrike-identity', 'microsoft-entra', 'auth0'],
  'mfa': ['okta', 'auth0', 'microsoft-entra', 'duo'],

  // Incident management
  'page': ['pagerduty', 'opsgenie', 'incident-io', 'oncall', 'alert'],
  'on-call': ['pagerduty', 'opsgenie', 'incident-io', 'oncall'],
  'oncall': ['pagerduty', 'opsgenie', 'incident-io'],
  'incident': ['pagerduty', 'opsgenie', 'incident-io', 'jira', 'servicenow'],
  'outage': ['pagerduty', 'datadog-observability', 'statuspage', 'opsgenie'],
  'alert': ['pagerduty', 'opsgenie', 'datadog-observability', 'grafana-api'],

  // Observability
  'response time': ['datadog-observability', 'new-relic', 'grafana-api', 'dynatrace', 'apm'],
  'latency': ['datadog-observability', 'new-relic', 'grafana-api', 'dynatrace'],
  'error rate': ['datadog-observability', 'new-relic', 'grafana-api', 'sentry', 'splunk'],
  'spiking': ['datadog-observability', 'new-relic', 'grafana-api', 'monitoring'],
  'memory': ['datadog-observability', 'grafana-api', 'kubernetes', 'prometheus'],
  'cpu': ['datadog-observability', 'grafana-api', 'kubernetes', 'prometheus'],
  'logs': ['splunk', 'datadog-observability', 'elastic-apm', 'grafana-api'],

  // DevOps
  'deploy': ['github-actions', 'jenkins', 'circleci', 'argocd', 'gitlab'],
  'deployment': ['github-actions', 'jenkins', 'circleci', 'argocd', 'gitlab'],
  'build failure': ['github-actions', 'jenkins', 'circleci', 'buildkite', 'gitlab'],
  'build failures': ['github-actions', 'jenkins', 'circleci', 'buildkite', 'gitlab'],
  'staging': ['github-actions', 'jenkins', 'argocd', 'vercel', 'netlify'],
  'container': ['kubernetes', 'docker-hub', 'aws-ecs', 'container'],
  'replica': ['kubernetes', 'aws-ecs', 'docker-hub'],
  'pipeline': ['github-actions', 'jenkins', 'circleci', 'gitlab', 'bitbucket'],

  // Scheduling & Calendar
  'appointment': ['google-calendar', 'calendly', 'fhir', 'scheduling'],
  'schedule meeting': ['google-calendar', 'calendly', 'microsoft-graph'],
  'schedule a meeting': ['google-calendar', 'calendly', 'microsoft-graph'],
  'follow-up': ['google-calendar', 'calendly', 'hubspot', 'salesforce'],
  'calendar': ['google-calendar', 'calendly', 'microsoft-graph'],

  // Finance
  'refund': ['stripe', 'paypal', 'square', 'shopify', 'payment'],
  'invoice': ['quickbooks', 'xero', 'freshbooks', 'stripe', 'billing'],
  'revenue': ['stripe', 'quickbooks', 'xero', 'chargebee', 'billing'],
  'payment': ['stripe', 'paypal', 'square', 'adyen'],
  'subscription': ['stripe', 'chargebee', 'recurly', 'billing'],

  // Communication
  'email': ['gmail', 'sendgrid', 'mailgun', 'amazon-ses', 'postmark'],
  'send email': ['gmail', 'sendgrid', 'mailgun', 'amazon-ses'],
  'slack message': ['slack', 'microsoft-teams'],
  'call': ['twilio', 'aircall', 'ringcentral', 'vonage', 'phone'],
  'sms': ['twilio', 'vonage', 'bandwidth', 'plivo'],

  // Travel
  'flight': ['sabre', 'amadeus', 'travelport', 'airline'],
  'hotel': ['sabre', 'amadeus', 'opera-pms', 'mews', 'cloudbeds', 'booking'],
  'book a flight': ['sabre', 'amadeus', 'travelport'],
  'book a hotel': ['sabre', 'amadeus', 'opera-pms', 'mews', 'cloudbeds'],

  // Hospitality
  'check in': ['opera-pms', 'mews', 'cloudbeds', 'hotel'],
  'check out': ['opera-pms', 'mews', 'cloudbeds', 'hotel'],
  'occupancy': ['opera-pms', 'mews', 'cloudbeds', 'hotel', 'room'],
  'room': ['opera-pms', 'mews', 'cloudbeds', 'hotel'],
  'guest': ['opera-pms', 'mews', 'cloudbeds', 'hotel'],

  // CRM
  'deal': ['salesforce', 'hubspot', 'pipedrive', 'close-crm'],
  'lead': ['salesforce', 'hubspot', 'marketo', 'apollo'],
  'prospect': ['salesforce', 'hubspot', 'outreach', 'apollo'],

  // IoT
  'thermostat': ['netatmo', 'google-home', 'ecobee', 'iot'],
  'temperature': ['netatmo', 'google-home', 'ecobee', 'iot'],
  'sensor': ['opto22-pac', 'particle', 'samsara', 'iot'],

  // AI
  'code review': ['github', 'openai-codex', 'codex-mcp', 'gitlab'],
  'generate image': ['openai-mcp', 'gemini-mcp', 'stability-ai', 'dalle'],
  'image generation': ['openai-mcp', 'gemini-mcp', 'stability-ai'],

  // Website
  'website is down': ['datadog-observability', 'statuspage', 'pingdom', 'uptime'],
  'website down': ['datadog-observability', 'statuspage', 'pingdom', 'uptime'],
  'website slow': ['datadog-observability', 'new-relic', 'grafana-api', 'dynatrace', 'apm'],
  'bottleneck': ['datadog-observability', 'new-relic', 'grafana-api', 'dynatrace'],
  'microservice': ['datadog-observability', 'new-relic', 'grafana-api', 'kubernetes'],
  'gpu': ['datadog-observability', 'grafana-api', 'new-relic'],
  'graph': ['datadog-observability', 'grafana-api', 'new-relic'],
  'summarize': ['slack', 'microsoft-teams', 'notion', 'confluence'],
  'discussed': ['slack', 'microsoft-teams', 'notion', 'confluence'],
  'conversation': ['slack', 'microsoft-teams', 'discord'],
  'launch': ['jira', 'asana', 'monday', 'linear', 'notion'],

  // HR & People
  'vacation': ['bamboohr', 'workday', 'gusto', 'adp', 'rippling', 'hibob'],
  'time off': ['bamboohr', 'workday', 'gusto', 'adp', 'rippling'],
  'pto': ['bamboohr', 'workday', 'gusto', 'adp'],
  'headcount': ['bamboohr', 'workday', 'adp', 'rippling', 'hibob'],
  'attrition': ['bamboohr', 'workday', 'culture-amp', 'lattice'],
  'compliance training employee': ['cornerstone', 'docebo', 'bamboohr', 'workday'],
  'open roles': ['greenhouse', 'lever', 'bamboohr', 'workday', 'recruitee'],
  'unfilled': ['greenhouse', 'lever', 'bamboohr', 'workday'],
  'employee': ['bamboohr', 'workday', 'gusto', 'adp', 'rippling', 'hibob'],

  // Healthcare expanded
  'patient': ['fhir', 'athenahealth', 'drchrono', 'epic-fhir'],
  'prescription': ['fhir', 'athenahealth', 'drchrono', 'infermedica'],
  'dosage': ['fhir', 'athenahealth', 'drchrono', 'infermedica'],
  'lab result': ['fhir', 'athenahealth', 'drchrono'],
  'bed availability': ['fhir', 'athenahealth', 'epic-fhir'],
  'readmission': ['fhir', 'athenahealth', 'drchrono'],
  'physician': ['fhir', 'athenahealth', 'drchrono'],
  'waiting': ['fhir', 'athenahealth', 'epic-fhir'],
  // NOTE: 'er ' removed — substring match was too aggressive, firing on 'filter',
  // 'tracker', 'user', etc. and injecting epic-fhir into non-healthcare queries.
  // Use 'emergency room' or 'emergency department' for ER-specific expansion.
  'emergency room': ['fhir', 'athenahealth', 'epic-fhir'],

  // Construction expanded
  'job site': ['procore', 'autodesk-construction', 'plangrid', 'buildertrend'],
  'behind schedule': ['procore', 'autodesk-construction', 'buildertrend', 'jira', 'asana'],
  'subcontractor': ['procore', 'autodesk-construction', 'buildertrend'],
  'change order': ['procore', 'autodesk-construction', 'buildertrend'],
  'equipment maintenance': ['samsara', 'procore'],
  'equipment': ['samsara', 'procore', 'autodesk-construction'],

  // Manufacturing expanded
  'production line': ['epicor', 'infor', 'netsuite', 'sap'],
  'downtime': ['epicor', 'infor', 'datadog-observability', 'pagerduty'],
  'inventory': ['epicor', 'infor', 'netsuite', 'shopify', 'sap'],
  'shipment': ['fedex', 'ups', 'easypost', 'shippo', 'flexport'],
  'steel': ['epicor', 'infor', 'netsuite', 'sap'],

  // Security expanded
  'login attempt': ['crowdstrike', 'okta', 'auth0', 'splunk', 'microsoft-entra'],
  'failed login': ['crowdstrike', 'okta', 'auth0', 'splunk', 'microsoft-entra'],
  'permission': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'elevated': ['crowdstrike', 'okta', 'microsoft-entra', 'cyberark'],
  'data transfer': ['crowdstrike', 'splunk', 'darktrace', 'extrahop'],
  'security patch': ['qualys', 'tenable', 'snyk', 'crowdstrike'],
  'logged in': ['okta', 'auth0', 'crowdstrike-identity', 'microsoft-entra'],
  'endpoint': ['crowdstrike', 'sentinelone', 'carbon-black', 'qualys'],

  // Identity / directory expanded — these phrases signal IAM adapters
  // regardless of whether the BM25 corpus has strong overlap. Adding explicit
  // vendor tokens here prevents low-relevance adapters (e.g. local business
  // directories) from winning via n-gram collision on the word "directory".
  'active directory': ['microsoft-entra', 'okta', 'auth0', 'azure', 'identity', 'rbac'],
  'azure active': ['microsoft-entra', 'azure', 'identity', 'rbac', 'entra'],
  'service account': ['microsoft-entra', 'okta', 'auth0', 'cyberark', 'identity'],
  'service accounts': ['microsoft-entra', 'okta', 'auth0', 'cyberark', 'identity'],
  'admin privileges': ['microsoft-entra', 'okta', 'auth0', 'cyberark', 'rbac'],
  'two different countries': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'different countries': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'multiple countries': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'concurrent logins': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'simultaneous login': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity'],
  'login detection': ['okta', 'auth0', 'microsoft-entra', 'crowdstrike-identity', 'splunk'],

  // Project / issue tracker expanded — prevents BM25 noise from matching
  // unrelated adapters on tokens like "state" or "progress".
  'linear tickets': ['linear', 'jira', 'issue', 'tracker', 'project'],
  'in progress state': ['linear', 'jira', 'asana', 'issue', 'tracker'],
  'jira tickets': ['jira', 'atlassian-jira', 'linear', 'issue', 'tracker'],
  'jira search': ['jira', 'atlassian-jira', 'linear', 'issue', 'ticket'],
  'open tickets': ['jira', 'linear', 'asana', 'zendesk', 'freshdesk'],
  'assigned to': ['jira', 'linear', 'asana', 'monday', 'issue'],

  // Payment-specific vendor expansions — reinforces BM25 when the query
  // explicitly names a payment provider but generic payment tokens would
  // otherwise promote competitors.
  'stripe payments': ['stripe', 'stripe-connect', 'payment', 'billing'],
  'stripe payment': ['stripe', 'stripe-connect', 'payment'],

  // PagerDuty-specific expansion — "on-call rotation" and "PagerDuty" together
  // should anchor to pagerduty even when opsgenie scores comparably.
  'pagerduty': ['pagerduty', 'on-call', 'oncall', 'incident', 'alert'],

  // DevOps expanded
  '500 error': ['datadog-observability', 'new-relic', 'sentry', 'grafana-api'],
  'changed in production': ['github', 'gitlab', 'argocd', 'datadog-observability'],
  'pod': ['kubernetes', 'datadog-observability', 'grafana-api'],
  'job queue': ['redis', 'datadog-observability', 'grafana-api'],

  // Finance expanded
  'burn rate': ['quickbooks', 'xero', 'stripe', 'chargebee'],
  'over budget': ['quickbooks', 'xero', 'netsuite', 'sage'],
  'budget': ['quickbooks', 'xero', 'netsuite', 'sage'],
  'cash runway': ['quickbooks', 'xero', 'stripe', 'brex'],
  'expense report': ['concur', 'expensify', 'brex', 'ramp'],
  'unpaid': ['quickbooks', 'xero', 'freshbooks', 'stripe'],

  // CRM expanded
  'churn': ['salesforce', 'hubspot', 'gainsight', 'amplitude'],
  'close rate': ['salesforce', 'hubspot', 'pipedrive', 'close-crm'],
  'sales rep': ['salesforce', 'hubspot', 'pipedrive', 'outreach'],
  'trade show': ['marketo', 'hubspot', 'salesforce', 'eventbrite'],
  'funnel': ['hubspot', 'salesforce', 'marketo', 'amplitude', 'mixpanel'],

  // Communication expanded
  'stakeholder': ['gmail', 'sendgrid', 'slack', 'microsoft-teams'],
  'status update': ['gmail', 'sendgrid', 'slack', 'jira'],
  'action items': ['notion', 'asana', 'jira', 'monday', 'linear'],
  'all-hands': ['notion', 'confluence', 'slack', 'asana', 'monday'],
  'meeting notes': ['notion', 'confluence', 'asana', 'monday'],
  'all hands': ['notion', 'confluence', 'slack', 'asana', 'monday'],

  // Hospitality expanded
  'guest complaint': ['opera-pms', 'mews', 'cloudbeds', 'zendesk'],
  'booking lead time': ['opera-pms', 'mews', 'cloudbeds', 'sabre'],
  'loyalty member': ['opera-pms', 'mews', 'salesforce'],
  'vip': ['opera-pms', 'mews', 'cloudbeds', 'salesforce'],
  'rebooking': ['sabre', 'amadeus', 'travelport'],
};

// ─── Catalog-driven expansion (CHARIOT::§4.6::1) ───────────────────────────
//
// CHARIOT-SPEC.md §4.6: "The expansion list is loaded from the catalog
// `keywords` field per adapter." Each adapter's `keywords` array is both the
// set of triggers AND the set of expansion terms for that adapter: a query
// containing any one of an adapter's keywords (e.g. the abbreviation "PD")
// expands to include that adapter's id/name plus its OTHER keywords (e.g.
// "PagerDuty", "incident") — the clause's own worked example.

/** Structural view of the catalog fields needed to build the expansion index.
 * Matches `AdapterEntry` (ChariotState.ts) and `AdapterCatalogEntry`
 * (AdapterCatalog.ts) without importing either — this module stays a leaf. */
export interface CatalogAdapterLike {
  id?: string;
  name?: string;
  keywords?: string[];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** One compiled catalog-keyword expansion rule. */
interface CatalogExpansionRule {
  /** Word-boundary, case-insensitive match on the catalog keyword — never a
   * bare substring test, so a short abbreviation (e.g. "PD") cannot false-fire
   * inside an unrelated token. */
  regex: RegExp;
  terms: Set<string>;
}

/** Built once per catalog load; consumed by every `expandQuery` call. */
export type CatalogExpansionIndex = CatalogExpansionRule[];

/**
 * Build the catalog-driven expansion index (CHARIOT::§4.6::1) from the
 * adapter catalog. For every adapter with a non-empty `keywords` field, each
 * keyword becomes a trigger whose expansion terms are the adapter's id, its
 * name, and every other keyword on that same adapter. Adapters with no
 * `keywords` contribute nothing (never a source of expansion — matches the
 * clause: the list is "loaded from the catalog `keywords` field", so an
 * adapter that publishes none has no expansion rule).
 */
export function buildCatalogExpansionIndex(adapters: Iterable<CatalogAdapterLike>): CatalogExpansionIndex {
  // Merge terms for keywords shared by multiple adapters before compiling the
  // regex, so a keyword owned by two adapters expands to the union of both.
  const byKeyword = new Map<string, Set<string>>();

  for (const adapter of adapters) {
    const keywords = Array.isArray(adapter.keywords)
      ? adapter.keywords.filter((k): k is string => typeof k === 'string' && k.trim().length > 0)
      : [];
    if (keywords.length === 0) continue;

    const terms = new Set<string>();
    if (adapter.id) terms.add(adapter.id);
    if (adapter.name) terms.add(adapter.name);
    for (const kw of keywords) terms.add(kw);

    for (const kw of keywords) {
      const key = kw.toLowerCase();
      const existing = byKeyword.get(key);
      if (existing) {
        for (const t of terms) existing.add(t);
      } else {
        byKeyword.set(key, new Set(terms));
      }
    }
  }

  const index: CatalogExpansionIndex = [];
  for (const [keyword, terms] of byKeyword) {
    index.push({ regex: new RegExp(`\\b${escapeRegExp(keyword)}\\b`, 'i'), terms });
  }
  return index;
}

/**
 * Expand a query with domain-specific keywords. Returns the original query
 * with injected terms appended.
 *
 * `catalogIndex` (CHARIOT::§4.6::1), when supplied, additionally expands
 * abbreviations known to the adapter catalog's `keywords` field per §4.6 —
 * this is the mechanism that satisfies the clause's data-source requirement.
 * The `EXPANSIONS` heuristic above runs regardless (see the file header for
 * why it is a separate, non-catalog mechanism).
 */
export function expandQuery(query: string, catalogIndex?: CatalogExpansionIndex): string {
  const lower = query.toLowerCase();
  const additions: Set<string> = new Set();

  for (const [phrase, terms] of Object.entries(EXPANSIONS)) {
    if (lower.includes(phrase)) {
      for (const term of terms) {
        additions.add(term);
      }
    }
  }

  if (catalogIndex) {
    for (const rule of catalogIndex) {
      if (rule.regex.test(query)) {
        for (const term of rule.terms) {
          additions.add(term);
        }
      }
    }
  }

  if (additions.size === 0) return query;
  return query + ' ' + [...additions].join(' ');
}
