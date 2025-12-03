#  Copyright 2023 Hathor Labs
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

from argparse import ArgumentParser, Namespace

from structlog import get_logger

logger = get_logger()


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument('--data', help='Data directory')

    return parser


def execute(args: Namespace) -> None:
    from hathor.conf.get_settings import get_global_settings
    from hathor.feature_activation.storage.feature_activation_storage import FeatureActivationStorage
    from hathor.storage import RocksDBStorage

    assert args.data is not None, '--data is required'

    rocksdb_storage = RocksDBStorage(path=args.data)
    feature_storage = FeatureActivationStorage(settings=get_global_settings(), rocksdb_storage=rocksdb_storage)

    logger.info('removing feature activation settings...')
    feature_storage.reset_settings()
    logger.info('reset complete')


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
