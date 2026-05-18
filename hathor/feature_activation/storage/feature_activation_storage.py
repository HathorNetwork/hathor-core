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
from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.exception import InitializationError
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.settings import Settings as FeatureActivationSettings
from hathor.storage import RocksDBStorage

_CF_NAME_META = b'feature-activation-metadata'
_KEY_SETTINGS = b'feature-activation-settings'

logger = get_logger()


class FeatureActivationStorage:
    __slots__ = ('_log', '_settings', '_db', '_cf_meta')

    def __init__(self, *, settings: HathorSettings, rocksdb_storage: RocksDBStorage) -> None:
        self._log = logger.new()
        self._settings = settings
        self._db = rocksdb_storage.get_db()
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)

    def reset_settings(self) -> None:
        """Reset feature settings from the database."""
        self._db.delete((self._cf_meta, _KEY_SETTINGS))

    def validate_settings(self) -> None:
        """Validate new feature settings against the previous configuration from the database."""
        new_settings = self._settings.FEATURE_ACTIVATION
        db_settings_bytes: bytes | None = self._db.get((self._cf_meta, _KEY_SETTINGS))

        if not db_settings_bytes:
            self._save_settings(new_settings)
            return

        db_settings: FeatureActivationSettings = FeatureActivationSettings.model_validate_json(db_settings_bytes)
        db_basic_settings = db_settings.model_copy(deep=True, update={'features': {}})
        new_basic_settings = new_settings.model_copy(deep=True, update={'features': {}})

        self._validate_basic_settings(db_basic_settings=db_basic_settings, new_basic_settings=new_basic_settings)
        self._validate_features(db_features=db_settings.features, new_features=new_settings.features)
        self._save_settings(new_settings)

    def _validate_basic_settings(
        self,
        *,
        db_basic_settings: FeatureActivationSettings,
        new_basic_settings: FeatureActivationSettings
    ) -> None:
        """Validate that the basic feature settings are the same."""
        if new_basic_settings != db_basic_settings:
            self._log.error(
                'Feature Activation basic settings are incompatible with previous settings.',
                previous_settings=db_basic_settings, new_settings=new_basic_settings
            )
            raise InitializationError()

    def _validate_features(
        self,
        *,
        db_features: dict[Feature, Criteria],
        new_features: dict[Feature, Criteria]
    ) -> None:
        """Validate that all previous features exist and are the same."""
        for db_feature, db_criteria in db_features.items():
            new_criteria = new_features.get(db_feature)

            if not new_criteria:
                self._log.error(
                    'Configuration for existing feature missing in new settings.',
                    feature=db_feature, previous_features=db_features, new_features=new_features
                )
                raise InitializationError()

            if new_criteria != db_criteria:
                self._log.error(
                    'Criteria for feature is different than previous settings.',
                    feature=db_feature, previous_criteria=db_criteria, new_criteria=new_criteria
                )
                raise InitializationError()

    def _save_settings(self, settings: FeatureActivationSettings) -> None:
        """Save feature settings to the database."""
        settings_bytes = settings.json_dumpb()

        self._db.put((self._cf_meta, _KEY_SETTINGS), settings_bytes)
