import base64
import os
import unittest.mock

import ocm
import pytest
import requests.exceptions

import odg.labels
import ocm_util
import secret_mgmt
import secret_mgmt.http


def _make_resource(
    name='my-image',
    version='1.0.0',
    extra_identity=None,
    resource_type='ociImage',
):
    return ocm.Resource(
        name=name,
        version=version,
        type=resource_type,
        access=ocm.OciAccess(imageReference=f'registry.example.com/{name}:{version}'),
        extraIdentity=extra_identity or {},
        labels=[],
    )


def _make_referencing_resource(
    name='my-image-sbom',
    version='1.0.0',
    resource_type='sbom',
    label_value=None,
    label_version='v1alpha1',
):
    if label_value is None:
        label_value = [{'identity': {'name': 'my-image'}}]

    labels = [
        ocm.Label(
            name=odg.labels.ArtifactReferencesLabel.name,
            value=label_value,
            version=label_version,
        ),
    ]

    return ocm.Resource(
        name=name,
        version=version,
        type=resource_type,
        access=ocm.OciAccess(imageReference=f'registry.example.com/{name}:{version}'),
        extraIdentity={},
        labels=labels,
    )


def _make_component(resources):
    component = unittest.mock.MagicMock(spec=ocm.Component)
    component.resources = resources
    return component


# --- _identity_matches ---


class TestIdentityMatches:
    def test_name_mismatch(self):
        resource = _make_resource(name='my-image')
        assert not ocm_util._identity_matches({'name': 'other-image'}, resource)

    def test_name_match_no_version(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert ocm_util._identity_matches({'name': 'my-image'}, resource)

    def test_version_match(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert ocm_util._identity_matches({'name': 'my-image', 'version': '1.0.0'}, resource)

    def test_version_mismatch(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'version': '2.0.0'},
            resource,
        )

    def test_extra_identity_exact_match(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_key_missing_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_extra_key_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64', 'os': 'linux'})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_value_mismatch(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'arm64'},
            resource,
        )


# --- iter_resources_referencing ---


class TestIterResourcesReferencing:
    def test_no_resources(self):
        component = _make_component([])
        resource = _make_resource()
        assert list(ocm_util.iter_resources_referencing(component, resource)) == []

    def test_resource_without_label(self):
        subject = _make_resource(name='my-image')
        candidate = _make_resource(name='other')
        component = _make_component([subject, candidate])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_label_wrong_version(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(
            label_value=[{'identity': {'name': 'my-image'}}],
            label_version='v1',
        )
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_label_matches(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(label_value=[{'identity': {'name': 'my-image'}}])
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [ref]

    def test_yields_any_resource_type_without_filter(self):
        subject = _make_resource(name='my-image')
        attestation = _make_referencing_resource(
            name='my-attestation',
            resource_type='attestation',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        component = _make_component([subject, attestation])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [attestation]

    def test_resource_type_filter(self):
        subject = _make_resource(name='my-image')
        sbom = _make_referencing_resource(
            name='my-sbom',
            resource_type='sbom',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        attestation = _make_referencing_resource(
            name='my-attestation',
            resource_type='attestation',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        component = _make_component([subject, sbom, attestation])
        result = list(
            ocm_util.iter_resources_referencing(
                component,
                subject,
                resource_type='sbom',
            ),
        )
        assert result == [sbom]

    def test_identity_no_match(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(label_value=[{'identity': {'name': 'other-image'}}])
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_multiple_entries_in_label(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(
            label_value=[
                {'identity': {'name': 'other-image'}},
                {'identity': {'name': 'my-image'}},
            ],
        )
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [ref]


# --- _iter_blob_descriptors_for_http ---


_HTTP_URL = 'https://example.com/path/to/file.tar.gz'


def _make_secret_factory(http_cfgs: list[secret_mgmt.http.HTTP] | None = None):
    """Build a minimal Secretsecret_factory that returns http_cfgs (or raises SecretTypeNotFound)."""
    secret_secret_factory = unittest.mock.MagicMock()
    if http_cfgs is None:
        secret_secret_factory.http.side_effect = secret_mgmt.SecretTypeNotFound('http')
    else:
        secret_secret_factory.http.return_value = http_cfgs
    return secret_secret_factory


def _make_response(
    content: bytes = b'hello world',
    content_type: str = 'application/octet-stream',
    content_length: int | None = None,
    status_code: int = 200,
) -> unittest.mock.MagicMock:
    """Return a mock requests.Response whose iter_content yields content in one chunk."""
    resp = unittest.mock.MagicMock()
    resp.status_code = status_code
    resp.headers = {'Content-Type': content_type}
    if content_length is not None:
        resp.headers['Content-Length'] = str(content_length)
    resp.iter_content.return_value = iter([content])
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=resp)
    else:
        resp.raise_for_status.return_value = None
    return resp


def test_iter_blob_descriptors_for_http_no_secret_config_makes_unauthenticated_request():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=None)
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        results = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    mock_req.assert_called_once()
    call_kwargs = mock_req.call_args.kwargs
    assert call_kwargs['auth'] is None
    assert 'Authorization' not in call_kwargs['headers']
    assert call_kwargs['verify'] is True
    assert call_kwargs['cert'] is None
    assert len(results) == 1


def test_iter_blob_descriptors_for_http_basic_auth_passed_to_requests():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        username='alice',
        password='secret',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    call_kwargs = mock_req.call_args.kwargs
    assert call_kwargs['auth'] == ('alice', 'secret')
    assert 'Authorization' not in call_kwargs['headers']


def test_iter_blob_descriptors_for_http_bearer_token_sent_as_authorization_header():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        identity_token='mytoken',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    call_kwargs = mock_req.call_args.kwargs
    assert call_kwargs['auth'] is None
    assert call_kwargs['headers']['Authorization'] == 'Bearer mytoken'


def test_iter_blob_descriptors_for_http_bearer_token_takes_precedence_over_basic_auth():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        username='alice',
        password='secret',
        identity_token='mytoken',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    call_kwargs = mock_req.call_args.kwargs
    assert call_kwargs['auth'] is None
    assert call_kwargs['headers']['Authorization'] == 'Bearer mytoken'


def test_iter_blob_descriptors_for_http_mtls_writes_cert_and_key_to_tempfiles():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        certificate='CERT_PEM',
        private_key='KEY_PEM',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    cert = mock_req.call_args.kwargs['cert']
    assert cert is not None
    cert_path, key_path = cert
    assert not os.path.exists(cert_path)
    assert not os.path.exists(key_path)


def test_iter_blob_descriptors_for_http_mtls_tempfiles_cleaned_up_even_on_http_error():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        certificate='CERT_PEM',
        private_key='KEY_PEM',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response(status_code=500)

    created_paths = []

    def tracking_request(**kwargs):
        cert = kwargs.get('cert')
        if cert:
            created_paths.extend(cert)
        return response

    with unittest.mock.patch('requests.request', side_effect=tracking_request):
        with pytest.raises(requests.exceptions.HTTPError):
            list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    for path in created_paths:
        assert not os.path.exists(path)


def test_iter_blob_descriptors_for_http_custom_ca_sets_verify_to_ca_file_path():
    http_cfg = secret_mgmt.http.HTTP(
        url_prefixes=['https://example.com/'],
        certificate_authority='CA_PEM',
    )
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert isinstance(mock_req.call_args.kwargs['verify'], str)


def test_iter_blob_descriptors_for_http_no_ca_uses_default_tls_verification():
    http_cfg = secret_mgmt.http.HTTP(url_prefixes=['https://example.com/'])
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[http_cfg])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['verify'] is True


def test_iter_blob_descriptors_for_http_plain_http_url_forwarded_as_is():
    access = ocm.HTTPAccess(url='http://internal.example.com/file.bin')
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['url'] == 'http://internal.example.com/file.bin'


def test_iter_blob_descriptors_for_http_default_verb_is_get():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['method'] == 'GET'


def test_iter_blob_descriptors_for_http_custom_verb_forwarded():
    access = ocm.HTTPAccess(url=_HTTP_URL, verb='POST')
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['method'] == 'POST'


def test_iter_blob_descriptors_for_http_extra_headers_forwarded():
    access = ocm.HTTPAccess(url=_HTTP_URL, header={'X-Custom': 'value'})
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['headers']['X-Custom'] == 'value'


def test_iter_blob_descriptors_for_http_base64_body_decoded_before_sending():
    raw = b'{"key": "val"}'
    access = ocm.HTTPAccess(
        url=_HTTP_URL,
        verb='POST',
        body=base64.b64encode(raw).decode(),
    )
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['data'] == raw


def test_iter_blob_descriptors_for_http_no_body_sends_none():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['data'] is None


def test_iter_blob_descriptors_for_http_redirects_followed_by_default():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['allow_redirects'] is True


def test_iter_blob_descriptors_for_http_no_redirect_flag_disables_redirects():
    access = ocm.HTTPAccess(url=_HTTP_URL, noRedirect=True)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response) as mock_req:
        list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert mock_req.call_args.kwargs['allow_redirects'] is False


def test_iter_blob_descriptors_for_http_size_from_content_length():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response(b'hello', content_length=5)

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.size == 5
    assert b''.join(desc.content) == b'hello'


def test_iter_blob_descriptors_for_http_size_buffered_when_no_content_length():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response(b'hello world')  # no Content-Length

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.size == 11
    assert b''.join(desc.content) == b'hello world'


def test_iter_blob_descriptors_for_http_name_derived_from_url():
    access = ocm.HTTPAccess(url='https://example.com/assets/archive.tar.gz')
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.name == 'archive.tar.gz'


def test_iter_blob_descriptors_for_http_name_derived_from_url_with_trailing_slash():
    access = ocm.HTTPAccess(url='https://example.com/assets/archive.tar.gz/')
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response()

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.name == 'archive.tar.gz'


def test_iter_blob_descriptors_for_http_access_media_type_takes_precedence():
    access = ocm.HTTPAccess(url=_HTTP_URL, mediaType='application/x-tar')
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response(content_type='text/plain')

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.media_type == 'application/x-tar'


def test_iter_blob_descriptors_for_http_content_type_header_used_when_no_access_media_type():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response(content_type='application/zip')

    with unittest.mock.patch('requests.request', return_value=response):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.media_type == 'application/zip'


def test_iter_blob_descriptors_for_http_fallback_media_type_when_neither_set():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    resp = _make_response()
    resp.headers = {}  # strip Content-Type entirely

    with unittest.mock.patch('requests.request', return_value=resp):
        (desc,) = list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))

    assert desc.media_type == 'application/octet-stream'


def test_iter_blob_descriptors_for_http_http_error_raises():
    access = ocm.HTTPAccess(url=_HTTP_URL)
    secret_factory = _make_secret_factory(http_cfgs=[])
    response = _make_response(status_code=404)

    with unittest.mock.patch('requests.request', return_value=response):
        with pytest.raises(requests.exceptions.HTTPError):
            list(ocm_util._iter_blob_descriptors_for_http(access, secret_factory))
