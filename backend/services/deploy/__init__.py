from services.deploy.service import DeployService, _register_bus_subscriber

# Importing the package wires the bus subscriber (same policy as
# webhook_service): any certificate.issued/renewed event is turned into
# durable DeployDelivery rows for matching bindings.
_register_bus_subscriber()

__all__ = ['DeployService']
