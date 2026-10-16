import dataclasses
import logging
import tempfile

import secret_mgmt


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class HTTP:
    url_prefixes: list[str]
    username: str | None = None
    password: str | None = None
    identity_token: str | None = None
    certificate: str | None = None
    private_key: str | None = None
    certificate_authority: str | None = None

    def __post_init__(self):
        if (self.username or self.password) and self.identity_token:
            logger.warning(
                'Both basic auth credentials and a bearer token were set for HTTP, will use the '
                'bearer token only',
            )

        if bool(self.certificate) != bool(self.private_key):
            raise ValueError('HTTP mTLS requires both certificate and private_key to be set')

    def url_matches(self, url: str) -> bool:
        return any(url.startswith(prefix) for prefix in self.url_prefixes)

    def auth_config(self) -> tuple[tuple[str, str] | None, dict[str, str]]:
        """
        Returns (basic_auth, extra_headers).
        Bearer token takes precedence over basic auth per OCM credential spec.
        """
        if self.identity_token:
            return None, {'Authorization': f'Bearer {self.identity_token}'}
        if self.username and self.password:
            return (self.username, self.password), {}
        return None, {}

    def tls_config(
        self,
    ) -> tuple[tuple[str, str] | None, str | bool, list]:
        """
        Returns (cert, verify, files) for use as requests' `cert` and `verify` kwargs.

        The caller must clean up `files` after the request completes.
        """
        cert = None
        verify = True
        files = []

        def _write_to_temporary_file(content: str) -> str:
            file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
            file.write(content.encode())
            file.flush()
            file.close()
            return file.name

        if self.certificate and self.private_key:
            cert_file = _write_to_temporary_file(self.certificate)
            files.append(cert_file)
            key_file = _write_to_temporary_file(self.private_key)
            files.append(key_file)

            cert = (cert_file, key_file)

        if self.certificate_authority:
            ca_file = _write_to_temporary_file(self.certificate_authority)
            files.append(ca_file)

            verify = ca_file

        return cert, verify, files


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    url: str,
    absent_ok: bool = True,
) -> HTTP | None:
    try:
        http_cfgs: list[HTTP] = secret_factory.http()
    except secret_mgmt.SecretTypeNotFound:
        if absent_ok:
            return None
        raise

    matching = [cfg for cfg in http_cfgs if cfg.url_matches(url)]

    if not matching:
        if absent_ok:
            return None
        raise ValueError(f'no HTTP credentials found for {url=}')

    # most specific match = longest prefix
    return max(matching, key=lambda cfg: max(len(p) for p in cfg.url_prefixes))
