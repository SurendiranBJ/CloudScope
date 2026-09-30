"""
CloudScope Prometheus metrics registry and definitions.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# HTTP Metrics
http_requests_total = Counter(
    "cloudscope_http_requests_total",
    "Total count of HTTP requests received",
    ["method", "endpoint", "status_code"]
)

http_request_duration_seconds = Histogram(
    "cloudscope_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# Scan Metrics
scan_total = Counter(
    "cloudscope_scan_total",
    "Total number of scans initiated",
    ["trigger_type", "status"]
)

scan_failures_total = Counter(
    "cloudscope_scan_failures_total",
    "Total number of failed scans",
    ["reason"]
)

scan_duration_seconds = Histogram(
    "cloudscope_scan_duration_seconds",
    "Total scan execution time in seconds",
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
)

# Collector Metrics
collector_total = Counter(
    "cloudscope_collector_total",
    "Total AWS collector executions",
    ["collector", "region"]
)

collector_failures_total = Counter(
    "cloudscope_collector_failures_total",
    "Total AWS collector failures",
    ["collector", "region"]
)

collector_duration_seconds = Histogram(
    "cloudscope_collector_duration_seconds",
    "AWS collector execution time in seconds",
    ["collector", "region"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
)

# Security Graph & Finding Gauges
findings_total = Gauge(
    "cloudscope_findings_total",
    "Current total findings by severity and status",
    ["severity", "status"]
)

attack_paths_total = Gauge(
    "cloudscope_attack_paths_total",
    "Current total attack paths identified",
    ["risk_level"]
)

graph_nodes = Gauge(
    "cloudscope_graph_nodes",
    "Current number of nodes in security topology graph"
)

graph_edges = Gauge(
    "cloudscope_graph_edges",
    "Current number of edges in security topology graph"
)

# Copilot Metrics
copilot_requests_total = Counter(
    "cloudscope_copilot_requests_total",
    "Total Gemini Copilot requests handled",
    ["status"]
)

copilot_latency_seconds = Histogram(
    "cloudscope_copilot_latency_seconds",
    "Gemini Copilot request duration in seconds",
    buckets=[0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0]
)

# Rate Limiter Metrics
rate_limit_rejections_total = Counter(
    "cloudscope_rate_limit_rejections_total",
    "Total rate limit rejections (HTTP 429)",
    ["category"]
)

# Phase 3 Observability Metrics
attack_paths_analyzed_total = Counter(
    "cloudscope_attack_paths_analyzed_total",
    "Total attack paths analyzed"
)

attack_paths_truncated_total = Counter(
    "cloudscope_attack_paths_truncated_total",
    "Total attack paths truncated due to bounds or timeouts",
    ["reason"]
)

path_traversal_duration_seconds = Histogram(
    "cloudscope_path_traversal_duration_seconds",
    "Attack path traversal latency in seconds",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

cloudtrail_events_normalized_total = Counter(
    "cloudscope_cloudtrail_events_normalized_total",
    "Total CloudTrail events normalized"
)

cloudtrail_correlations_total = Counter(
    "cloudscope_cloudtrail_correlations_total",
    "Total CloudTrail correlations produced",
    ["confidence"]
)

cloudtrail_correlation_duration_seconds = Histogram(
    "cloudscope_cloudtrail_correlation_duration_seconds",
    "CloudTrail correlation latency in seconds",
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0]
)

findings_created_total = Counter(
    "cloudscope_findings_created_total",
    "Total security findings created",
    ["source"]
)

findings_updated_total = Counter(
    "cloudscope_findings_updated_total",
    "Total security findings updated",
    ["status"]
)

findings_reopened_total = Counter(
    "cloudscope_findings_reopened_total",
    "Total security findings transitioned back to OPEN"
)

risk_evaluations_total = Counter(
    "cloudscope_risk_evaluations_total",
    "Total risk evaluations performed",
    ["model_version"]
)

evidence_retrieval_duration_seconds = Histogram(
    "cloudscope_evidence_retrieval_duration_seconds",
    "Evidence retrieval duration in seconds",
    buckets=[0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0]
)

copilot_failures_total = Counter(
    "cloudscope_copilot_failures_total",
    "Total Copilot AI request failures",
    ["reason"]
)


def get_metrics_output() -> tuple[bytes, str]:
    """Return raw Prometheus metrics string and Content-Type."""
    return generate_latest(), CONTENT_TYPE_LATEST
