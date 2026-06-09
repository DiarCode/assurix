"""Offensive security toolkit for the PentesterAgent."""

from .payload_generator import PayloadGenerator, Payload
from .payload_mutator import PayloadMutator, Gene, MutationResult
from .fuzzer import Fuzzer, FuzzResult
from .brute_force import BruteForcer, BruteResult
from .port_scanner import PortScanner, PortResult
from .request_interceptor import RequestInterceptor, InterceptResult
from .auth_tester import AuthTester, AuthResult
from .subdomain_enum import SubdomainEnumerator, SubdomainResult
from .response_dedup import ResponseDeduplicator, DedupResult
from .idor_validator import IDORValidator, IDORResult
from .severity_adjuster import SeverityAdjuster
from .timing_analyzer import TimingAnalyzer, TimingResult
from .credential_tester import CredentialTester, CredentialResult
from .graphql_scanner import GraphQLScanner, GraphQLResult
from .websocket_scanner import WebSocketScanner, WebSocketResult
from .session import SharedSessionManager
from .vuln_pipelines import XSSPipeline, SQLiPipeline, SSRFPipeline, CommandInjectionPipeline, VulnResult
from .business_logic_pipeline import WorkflowAuthPipeline, RaceConditionPipeline, IDORPipeline, BusinessRulePipeline, BusinessLogicResult
from .protocol import ToolProtocol
from .registry import ToolRegistry, get_registry

__all__ = [
    "PayloadGenerator", "Payload",
    "PayloadMutator", "Gene", "MutationResult",
    "Fuzzer", "FuzzResult",
    "BruteForcer", "BruteResult",
    "PortScanner", "PortResult",
    "RequestInterceptor", "InterceptResult",
    "AuthTester", "AuthResult",
    "SubdomainEnumerator", "SubdomainResult",
    "ResponseDeduplicator", "DedupResult",
    "IDORValidator", "IDORResult",
    "SeverityAdjuster",
    "TimingAnalyzer", "TimingResult",
    "CredentialTester", "CredentialResult",
    "GraphQLScanner", "GraphQLResult",
    "WebSocketScanner", "WebSocketResult",
    "SharedSessionManager",
    "XSSPipeline", "SQLiPipeline", "SSRFPipeline", "CommandInjectionPipeline", "VulnResult",
    "WorkflowAuthPipeline", "RaceConditionPipeline", "IDORPipeline", "BusinessRulePipeline", "BusinessLogicResult",
    "ToolProtocol",
    "ToolRegistry", "get_registry",
]
