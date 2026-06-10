---
description: "Investigate the feature activation system, bit signaling, feature states, and feature-gated behavior in hathor-core"
---

# Feature Activation System

When the user asks about feature activation, bit signaling, or feature flags, follow these steps:

## Step 1: Read the core feature activation files
- `hathor/feature_activation/feature.py` — `Feature` enum listing all features and their activation parameters
- `hathor/feature_activation/feature_service.py` — `FeatureService` manages feature state transitions
- `hathor/feature_activation/bit_signaling_service.py` — handles miner bit signaling in blocks

## Step 2: Understand the state machine
Features follow this state machine:
```
DEFINED → STARTED → MUST_SIGNAL → LOCKED_IN → ACTIVE
                                            → FAILED
```
- `hathor/feature_activation/model/feature_state.py` — `FeatureState` enum with all states
- Each state transition depends on block heights and signaling thresholds

## Step 3: Understand bit signaling
- Miners signal support for features by setting bits in block headers
- Each feature is assigned a specific bit position
- The signaling service counts bits over evaluation windows to determine if threshold is met

## Step 4: Check feature-gated behavior
Search the codebase for uses of the feature activation system:
- Preferred: `Features.from_vertex(settings=..., feature_service=..., vertex=block)` returns a `Features` dataclass with all feature states
- Alternative: `feature_service.is_feature_active(vertex=vertex, feature=Feature.X)` for single checks
- Features gate new behavior that should only activate after network consensus

## Step 5: Check feature configuration
- Features have parameters: start height, timeout height, threshold percentage
- These may differ between mainnet, testnet, and other networks
- Check settings/configuration files for network-specific feature parameters

## Step 6: Explain
Present the feature's current state, activation criteria, and any gated behavior relevant to the user's question.
