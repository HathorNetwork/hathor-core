#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from pathlib import Path
from typing import Callable

from twisted.internet.protocol import Factory

from hathor.multiprocess.main_subprocess_runner import SubprocessFactoryArgs, main_subprocess_runner

MAIN_P2P_CLIENT_CONNECTION_FILE = Path(__file__)


def build_hathor_client_factory(factory_args: SubprocessFactoryArgs) -> tuple[Factory, Callable[[], None]]:
    raise NotImplementedError


if __name__ == '__main__':
    main_subprocess_runner(build_hathor_client_factory)
