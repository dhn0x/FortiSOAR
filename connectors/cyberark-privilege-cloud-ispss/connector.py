"""
Author: dhaneshwar
Custom CyberArk Privilege Cloud connector for FortiSOAR.
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('cyberark-privilege-cloud-ispss')


class CyberArkPrivilegeCloud(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            op_func = operations.get(operation)
            if not op_func:
                raise ConnectorError('Unsupported operation: {0}'.format(operation))
            return op_func[0](config, operation_params)
        except Exception as err:
            logger.error('Operation [{0}] failed: {1}'.format(operation, err))
            raise ConnectorError('{0}'.format(err))

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
