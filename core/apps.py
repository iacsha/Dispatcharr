from django.apps import AppConfig
from django.conf import settings
import logging

# Define TRACE level (5 is below DEBUG which is 10)
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

# Add trace method to the Logger class
def trace(self, message, *args, **kwargs):
    """Log a message with TRACE level (more detailed than DEBUG)"""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)

# Add the trace method to the Logger class
logging.Logger.trace = trace


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        # Import signals to ensure they get registered
        import core.signals
        from dispatcharr.app_initialization import should_skip_initialization

        from django.conf import settings as django_settings
        from dispatcharr.log_collector import apply_settings

        # Only run in the main process (not in management commands, migrations, or workers)
        if should_skip_initialization():
            return

        try:
            from core.models import CoreSettings

            apply_settings(
                getattr(django_settings, "LOG_FILE_DIR", None),
                CoreSettings.get_system_settings(),
            )
        except Exception:
            # Database not migrated yet: the collector keeps its defaults.
            pass

        self._check_credentials_key()

        # Sync developer notifications and check for version updates on startup
        self._sync_developer_notifications()

    def _check_credentials_key(self):
        """Log CRITICAL at startup if stored credentials don't open with the key."""
        from django.db import close_old_connections, connection
        import logging

        try:
            from core.encryption import check_stored_credentials

            check_stored_credentials(connection)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Credentials key check skipped: {e}")
        finally:
            close_old_connections()

    def _sync_developer_notifications(self):
        """Sync developer notifications from JSON file to database."""
        from django.db import close_old_connections
        import logging

        logger = logging.getLogger(__name__)

        try:
            from core.developer_notifications import sync_developer_notifications
            sync_developer_notifications()
        except Exception as e:
            logger.warning(f"Failed to sync developer notifications on startup: {e}")
        finally:
            # Boot ORM runs outside a request cycle; return geventpool checkouts.
            close_old_connections()

