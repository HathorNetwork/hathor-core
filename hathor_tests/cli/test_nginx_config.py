# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from io import StringIO

import pytest

from hathor_cli.nginx_config import generate_nginx_config


class TestGenerateNginxConfig:
    def test_default_api_version_is_v1a_only(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        out = StringIO()
        generate_nginx_config(openapi, out_file=out)
        config = out.getvalue()

        # a path without `x-api-versions` is exposed only under the default (v1a)
        assert 'location ~ ^/v1a/example/?$ {' in config
        assert 'location ~ ^/v2/example/?$ {' not in config
        # websockets are unversioned and follow the default, so only v1a serves them
        assert 'location ~ ^/v1a/ws/?$ {' in config
        assert 'location ~ ^/v2/ws/?$ {' not in config
        # a `403` fallback is emitted for every served version, the catch-all `404` exactly once
        assert 'location /v1a {' in config
        assert 'location /v2 {' in config
        assert config.count('location / {') == 1

    def test_explicit_both_versions_emits_under_both(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'x-api-versions': ['v1a', 'v2'],
                    'get': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        out = StringIO()
        generate_nginx_config(openapi, out_file=out)
        config = out.getvalue()

        assert 'location ~ ^/v1a/example/?$ {' in config
        assert 'location ~ ^/v2/example/?$ {' in config

    def test_v2_only_excludes_v1a(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'x-api-versions': ['v2'],
                    'get': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        out = StringIO()
        generate_nginx_config(openapi, out_file=out)
        config = out.getvalue()

        assert 'location ~ ^/v1a/example/?$ {' not in config
        assert 'location ~ ^/v2/example/?$ {' in config

    def test_operation_level_api_versions(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'public',
                        'x-api-versions': ['v1a', 'v2'],
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        out = StringIO()
        generate_nginx_config(openapi, out_file=out)
        config = out.getvalue()

        assert 'location ~ ^/v1a/example/?$ {' in config
        assert 'location ~ ^/v2/example/?$ {' in config

    def test_unknown_api_version_raises_error(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'x-api-versions': ['v1a', 'v3'],
                    'get': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        with pytest.raises(ValueError, match='unknown API version `v3`'):
            generate_nginx_config(openapi, out_file=StringIO())

    def test_conflicting_public_api_versions_raise_error(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'public',
                        'x-api-versions': ['v1a', 'v2'],
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                    'post': {
                        'x-visibility': 'public',
                        'x-api-versions': ['v1a'],
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                },
            },
        }

        with pytest.raises(ValueError, match='conflicting x-api-versions'):
            generate_nginx_config(openapi, out_file=StringIO())

    def test_mixed_visibility_excludes_private_method_from_limit_except(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'private',
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                    'post': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        out = StringIO()
        generate_nginx_config(openapi, out_file=out)
        config = out.getvalue()

        # without `x-api-versions` the path defaults to v1a only
        assert 'location ~ ^/v1a/example/?$ {' in config
        assert 'location ~ ^/v2/example/?$ {' not in config
        assert config.count('limit_except OPTIONS POST { deny all; }') == 1
        assert 'limit_except OPTIONS GET POST { deny all; }' not in config

    def test_conflicting_public_rate_limits_raise_error(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                    'post': {
                        'x-visibility': 'public',
                        'x-rate-limit': {
                            'global': [{'rate': '10r/s', 'burst': 10, 'delay': 0}],
                        },
                    },
                },
            },
        }

        with pytest.raises(ValueError, match='conflicting x-rate-limit'):
            generate_nginx_config(openapi, out_file=StringIO())

    def test_private_operation_visibility_does_not_warn_as_fallback(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'private',
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                },
            },
        }

        generate_nginx_config(openapi, out_file=StringIO())

        captured = capsys.readouterr()
        assert 'Visibility not set for path `/example`' not in captured.err

    def test_conflicting_public_path_params_regex_raise_error(self) -> None:
        openapi = {
            'paths': {
                '/example/{value}': {
                    'get': {
                        'x-visibility': 'public',
                        'x-path-params-regex': {'value': '[0-9]+'},
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                    'post': {
                        'x-visibility': 'public',
                        'x-path-params-regex': {'value': '[a-z]+'},
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                },
            },
        }

        with pytest.raises(ValueError, match='conflicting x-path-params-regex'):
            generate_nginx_config(openapi, out_file=StringIO())

    def test_conflicting_public_proxy_buffers_raise_error(self) -> None:
        openapi = {
            'paths': {
                '/example': {
                    'get': {
                        'x-visibility': 'public',
                        'x-proxy-buffers': '16 16k',
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                    'post': {
                        'x-visibility': 'public',
                        'x-proxy-buffers': '32 16k',
                        'x-rate-limit': {
                            'global': [{'rate': '1r/s', 'burst': 1, 'delay': 0}],
                        },
                    },
                },
            },
        }

        with pytest.raises(ValueError, match='conflicting x-proxy-buffers'):
            generate_nginx_config(openapi, out_file=StringIO())
