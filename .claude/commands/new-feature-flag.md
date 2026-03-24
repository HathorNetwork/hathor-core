---
description: Add a new feature to the activation system
---

Add a new feature flag to the feature activation system: $ARGUMENTS

Steps:
1. Add the feature to the `Feature` enum in `hathor/feature_activation/feature.py`:
   ```python
   MY_FEATURE = 'MY_FEATURE'
   ```
   Note: Features should NEVER be removed from this enum to preserve history.

2. Add activation criteria in the network settings files (e.g., `hathor/conf/mainnet.py`, `hathor/conf/testnet.py`):
   ```python
   Feature.MY_FEATURE: Criteria(
       bit=<next_available_bit>,
       start_height=<height>,
       timeout_height=<height>,
       threshold=<int>,  # number of signaling blocks needed
       minimum_activation_height=<height>,
   )
   ```

3. Guard the new behavior in code using:
   ```python
   if feature_service.is_feature_active(Feature.MY_FEATURE, block=block):
       # new behavior
   ```

4. Add tests in `hathor_tests/feature_activation/` verifying:
   - Feature activates correctly after signaling threshold
   - Code behaves correctly both with feature active and inactive
   - Transition between states works properly
