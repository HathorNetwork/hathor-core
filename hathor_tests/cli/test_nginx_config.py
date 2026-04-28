# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import sys
from io import StringIO
from types import ModuleType, SimpleNamespace

import pytest

from hathor_cli.nginx_config import generate_nginx_config


class TestGenerateNginxConfig:
    @staticmethod
    def _stub_settings_modules(monkeypatch: pytest.MonkeyPatch) -> None:
        hathor_module = ModuleType('hathor')
        conf_module = ModuleType('hathor.conf')
        get_settings_module = ModuleType('hathor.conf.get_settings')

        def get_global_settings() -> SimpleNamespace:
            return SimpleNamespace(API_VERSION_PREFIX='v1a')

        setattr(get_settings_module, 'get_global_settings', get_global_settings)
        setattr(hathor_module, 'conf', conf_module)
        setattr(conf_module, 'get_settings', get_settings_module)

        monkeypatch.setitem(sys.modules, 'hathor', hathor_module)
        monkeypatch.setitem(sys.modules, 'hathor.conf', conf_module)
        monkeypatch.setitem(sys.modules, 'hathor.conf.get_settings', get_settings_module)

    def test_mixed_visibility_excludes_private_method_from_limit_except(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_settings_modules(monkeypatch)
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

        assert 'location ~ ^/v1a/example/?$ {' in config
        assert 'limit_except OPTIONS POST { deny all; }' in config
        assert 'limit_except OPTIONS GET POST { deny all; }' not in config

    def test_conflicting_public_rate_limits_raise_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_settings_modules(monkeypatch)
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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._stub_settings_modules(monkeypatch)
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

    def test_conflicting_public_path_params_regex_raise_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_settings_modules(monkeypatch)
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

    def test_conflicting_public_proxy_buffers_raise_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_settings_modules(monkeypatch)
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
