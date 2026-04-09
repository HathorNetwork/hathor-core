# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from logging import getLogger
from typing import TYPE_CHECKING, Any, Optional

from ipykernel.kernelapp import IPKernelApp as OriginalIPKernelApp

if TYPE_CHECKING:
    from hathor.manager import HathorManager


class IPKernelApp(OriginalIPKernelApp):
    def __init__(self, runtime_dir: Optional[str] = None):
        super().__init__()
        # https://traitlets.readthedocs.io/en/stable/config-api.html#traitlets.config.Application.logging_config
        self.logging_config: dict[str, Any] = {}  # empty out logging config
        # https://traitlets.readthedocs.io/en/stable/config-api.html#traitlets.config.LoggingConfigurable.log
        self.log = getLogger('hathor.ipykernel')  # use custom name for the logging adapter
        if runtime_dir is not None:
            # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.connection_dir
            # https://github.com/ipython/ipykernel/blob/main/ipykernel/kernelapp.py#L301-L320
            # if not defined now, when init_connection_file is called it will be set to 'kernel-<PID>.json', it is
            # defined now because it's more convenient to have a fixed path that doesn't depend on the PID of the
            # running process, which doesn't benefit us anyway since the data dir
            self.connection_dir = runtime_dir
            self.connection_file = 'kernel.json'
        # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.no_stderr
        self.no_stderr = True  # disable forwarding of stderr (because we use it for logging)

    # https://traitlets.readthedocs.io/en/stable/config-api.html#traitlets.config.Application.get_default_logging_config
    def get_default_logging_config(self) -> dict[str, Any]:
        # XXX: disable original logging setup
        return {"version": 1, "disable_existing_loggers": False}

    # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.init_signal
    def init_signal(self) -> None:
        # XXX: ignore registering of signals
        pass

    # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.log_connection_info
    def log_connection_info(self) -> None:
        # XXX: this method is only used to log this info, we can customize it freely
        self.log.info(f'ipykernel connection enabled at {self.abs_connection_file}')

    # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.configure_tornado_logger
    def configure_tornado_logger(self) -> None:
        # XXX: we already setup tornago logging on hathor_cli.util.setup_logging prevent this class from overriding it
        pass

    # https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.kernelapp.IPKernelApp.start
    def start(self):
        # XXX: custom start to prevent it from running an event loop and capturing KeyboardInterrupt
        self.kernel.start()


# https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html#ipykernel.embed.embed_kernel
def embed_kernel(manager: 'HathorManager', *,
                 runtime_dir: Optional[str] = None, extra_ns: dict[str, Any] = {}) -> None:
    """ Customized version of ipykernel.embed.embed_kernel that takes parameters specific to this project.

    In theory this method could be called multiple times, like the original ipykernel.embed.embed_kernel.
    """
    # get the app if it exists, or set it up if it doesn't
    if IPKernelApp.initialized():
        app = IPKernelApp.instance()
    else:
        app = IPKernelApp.instance(runtime_dir=runtime_dir)
        app.initialize([])
    app.kernel.user_ns = dict(manager=manager) | extra_ns
    app.shell.set_completer_frame()
    app.start()
