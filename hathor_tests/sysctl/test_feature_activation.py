# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
