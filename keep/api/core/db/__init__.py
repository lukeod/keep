"""
Database module - backward compatibility exports.

This file maintains backward compatibility by exporting all functions
from the split modules as if they were still in a single db.py file.

IMPORTANT: This is provided for backward compatibility during the migration.
New code should import directly from the specific modules for better clarity.
"""

# NOTE: The # noqa comments below are intentionally added to prevent autoflake
# from removing these imports. These wildcard imports are necessary for backward
# compatibility - they re-export all functions from the split modules so that
# existing code importing from keep.api.core.db continues to work without changes.

# Import and re-export everything from common
from keep.api.core.db._common import *  # noqa: F401,F403

# Import and re-export from all domain modules
from keep.api.core.db.action import *  # noqa: F401,F403
from keep.api.core.db.ai import *  # noqa: F401,F403
from keep.api.core.db.alert import *  # noqa: F401,F403
from keep.api.core.db.dashboard import *  # noqa: F401,F403
from keep.api.core.db.enrichment import *  # noqa: F401,F403
from keep.api.core.db.incident import *  # noqa: F401,F403
from keep.api.core.db.preset import *  # noqa: F401,F403
from keep.api.core.db.provider import *  # noqa: F401,F403
from keep.api.core.db.rule import *  # noqa: F401,F403
from keep.api.core.db.system import *  # noqa: F401,F403
from keep.api.core.db.tenant import *  # noqa: F401,F403
from keep.api.core.db.topology import *  # noqa: F401,F403
from keep.api.core.db.user import *  # noqa: F401,F403
from keep.api.core.db.workflow import *  # noqa: F401,F403

# Note: Models are not re-exported here. Import them directly from keep.api.models.db.*

# Import models for backward compatibility (from original db.py)
from keep.api.models.db.ai_external import *  # noqa: F401,F403
from keep.api.models.db.alert import *  # noqa: F401,F403
from keep.api.models.db.dashboard import *  # noqa: F401,F403
from keep.api.models.db.enrichment_event import *  # noqa: F401,F403
from keep.api.models.db.extraction import *  # noqa: F401,F403
from keep.api.models.db.incident import *  # noqa: F401,F403
from keep.api.models.db.maintenance_window import *  # noqa: F401,F403
from keep.api.models.db.mapping import *  # noqa: F401,F403
from keep.api.models.db.preset import *  # noqa: F401,F403
from keep.api.models.db.provider import *  # noqa: F401,F403
from keep.api.models.db.provider_image import *  # noqa: F401,F403
from keep.api.models.db.rule import *  # noqa: F401,F403
from keep.api.models.db.system import *  # noqa: F401,F403
from keep.api.models.db.tenant import *  # noqa: F401,F403
from keep.api.models.db.topology import *  # noqa: F401,F403
from keep.api.models.db.workflow import *  # noqa: F401,F403
from keep.api.models.incident import IncidentDto, IncidentDtoIn, IncidentSorting  # noqa: F401
from keep.api.models.time_stamp import TimeStampFilter  # noqa: F401
