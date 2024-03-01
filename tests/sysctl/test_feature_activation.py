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

from unittest.mock import Mock

from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature import Feature
from hathor.sysctl import FeatureActivationSysctl


def test_feature_activation_sysctl() -> None:
    bit_signaling_service_mock = Mock(spec_set=BitSignalingService)
    sysctl = FeatureActivationSysctl(bit_signaling_service_mock)

    bit_signaling_service_mock.get_support_features = Mock(return_value=[Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2])
    bit_signaling_service_mock.get_not_support_features = Mock(return_value=[Feature.NOP_FEATURE_3])
    bit_signaling_service_mock.get_best_block_signaling_features = Mock(return_value={Feature.NOP_FEATURE_1: Mock()})

    assert sysctl.get('supported_features') == ['NOP_FEATURE_1', 'NOP_FEATURE_2']
    assert sysctl.get('not_supported_features') == ['NOP_FEATURE_3']
    assert sysctl.get('signaling_features') == ['NOP_FEATURE_1']

    sysctl.unsafe_set('add_support', 'NOP_FEATURE_3')
    bit_signaling_service_mock.add_feature_support.assert_called_once_with(Feature.NOP_FEATURE_3)

    sysctl.unsafe_set('remove_support', 'NOP_FEATURE_1')
    bit_signaling_service_mock.remove_feature_support.assert_called_once_with(Feature.NOP_FEATURE_1)
