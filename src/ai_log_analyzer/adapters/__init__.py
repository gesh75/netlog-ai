"""Log source adapters — each yields LogEvent instances for the classifier."""
from ai_log_analyzer.adapters import network_tool
from ai_log_analyzer.adapters.file import parse_file, parse_lines
from ai_log_analyzer.adapters.frr import frr_docker_logs, parse_frr_line

__all__ = ["frr_docker_logs", "parse_frr_line", "parse_file", "parse_lines", "network_tool"]
