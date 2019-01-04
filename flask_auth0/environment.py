from typing import List

from env_process import process_environment_variable, SupportedBaseTypes

AUTH0_DOMAIN: str = process_environment_variable('AUTH0_DOMAIN', env_type=SupportedBaseTypes.STR)
AUTH0_API_AUDIENCE: str = process_environment_variable('AUTH0_API_AUDIENCE', env_type=SupportedBaseTypes.STR)
AUTH0_ALGORITHMS: List[str] = process_environment_variable('AUTH0_ALGORITHMS', env_type=SupportedBaseTypes.LIST_STR)
