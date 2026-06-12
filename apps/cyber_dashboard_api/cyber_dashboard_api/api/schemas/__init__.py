"""Schemas d'entree et de sortie des endpoints."""

from .errors import ErrorDetailSchema, ErrorInfoSchema, ErrorResponseSchema
from .alerts import (
    AlertDetailItemSchema,
    AlertDetailResponseSchema,
    AlertListItemSchema,
    AlertListResponseSchema,
)
from .attacks_collector_config import (
    AttacksCollectorConfigCreateRequestSchema,
    AttacksCollectorConfigListResponseSchema,
    AttacksCollectorConfigSchema,
    AttacksCollectorConfigUpdateRequestSchema,
    AttacksCollectorInventoryRequestResponseSchema,
)
from .attacks import AttackItemSchema, AttackListResponseSchema, AttackListQuerySchema
from .common import PaginationSchema, TimeRangeQuerySchema
from .cti_config import (
    CtiConfigListResponseSchema,
    CtiConfigSchema,
    CtiConfigUpdateRequestSchema,
)
from .cti_enrichment import (
    AbuseIpdbCategoryPercentageSchema,
    AbuseIpdbEnrichmentResponseSchema,
    GreyNoiseEnrichmentResponseSchema,
    IpDataEnrichmentResponseSchema,
    RdapEnrichmentResponseSchema,
    ShodanEnrichmentResponseSchema,
    VirusTotalAnalysisStatsSchema,
    VirusTotalEnrichmentResponseSchema,
)
from .dashboard import DashboardOverviewSchema
from .inventory import (
    SensorInventoryItemSchema,
    SensorInventoryResponseSchema,
    SourceItemSchema,
    SourceListResponseSchema,
    SourceRenameRequestSchema,
    SourceStatusUpdateRequestSchema,
    SourceColorUpdateRequestSchema,
)
from .retention_policies import (
    RetentionPolicyListResponseSchema,
    RetentionPolicySchema,
    RetentionPolicyUpdateRequestSchema,
)
from .smtp_config import SmtpConfigSchema, SmtpConfigUpdateRequestSchema
from .statistics import (
    AttackSummaryResponseSchema,
    AttackSourcePercentageSchema,
    AttackStatisticsResponseSchema,
    AttackSourceTimeseriesResponseSchema,
    AttackSourceTimeseriesSeriesSchema,
    AttackTypePercentageSchema,
    TopAttackTypesResponseSchema,
)
from .system import HealthcheckSchema

__all__ = [
    "AlertDetailItemSchema",
    "AlertDetailResponseSchema",
    "AlertListItemSchema",
    "AlertListResponseSchema",
    "AttacksCollectorConfigCreateRequestSchema",
    "AttacksCollectorConfigListResponseSchema",
    "AttacksCollectorConfigSchema",
    "AttacksCollectorConfigUpdateRequestSchema",
    "AttacksCollectorInventoryRequestResponseSchema",
    "AttackItemSchema",
    "AttackListQuerySchema",
    "AttackListResponseSchema",
    "AttackSourcePercentageSchema",
    "AttackSourceTimeseriesResponseSchema",
    "AttackSourceTimeseriesSeriesSchema",
    "AttackSummaryResponseSchema",
    "AttackStatisticsResponseSchema",
    "AttackTypePercentageSchema",
    "AbuseIpdbCategoryPercentageSchema",
    "AbuseIpdbEnrichmentResponseSchema",
    "GreyNoiseEnrichmentResponseSchema",
    "IpDataEnrichmentResponseSchema",
    "RdapEnrichmentResponseSchema",
    "ShodanEnrichmentResponseSchema",
    "VirusTotalAnalysisStatsSchema",
    "VirusTotalEnrichmentResponseSchema",
    "CtiConfigListResponseSchema",
    "CtiConfigSchema",
    "CtiConfigUpdateRequestSchema",
    "DashboardOverviewSchema",
    "ErrorDetailSchema",
    "ErrorInfoSchema",
    "ErrorResponseSchema",
    "HealthcheckSchema",
    "PaginationSchema",
    "RetentionPolicyListResponseSchema",
    "RetentionPolicySchema",
    "RetentionPolicyUpdateRequestSchema",
    "SensorInventoryItemSchema",
    "SensorInventoryResponseSchema",
    "SmtpConfigSchema",
    "SmtpConfigUpdateRequestSchema",
    "SourceItemSchema",
    "SourceListResponseSchema",
    "SourceRenameRequestSchema",
    "SourceStatusUpdateRequestSchema",
    "TimeRangeQuerySchema",
    "TopAttackTypesResponseSchema",
    "SourceColorUpdateRequestSchema",
]
