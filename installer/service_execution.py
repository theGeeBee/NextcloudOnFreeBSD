"""Explicit admission for reviewed prerelease collaboration runtime profiles.

Pure planning and legacy retained executors remain independent. Parsing a service
profile does not grant execution. native-v1 is admitted for disposable validation
after implementation review; native acceptance is a separate, unproven claim.
"""

EXECUTABLE_SERVICE_PROFILES = frozenset({"native-v1"})


def require_services_execution(config):
    profile = getattr(config, "service_profile", "")
    if profile and profile not in EXECUTABLE_SERVICE_PROFILES:
        raise ValueError(
            "Native collaboration services are available for planning only until "
            "their guarded deployment, network, lifecycle and verification "
            "integration is complete; no service installation was started"
        )
