# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from typing import Sequence

from hathorlib.nanocontracts.exception import NCInvalidAction
from hathorlib.nanocontracts.types import NCAction, NCActionType, TokenUid

MAX_ACTIONS_LEN: int = 16
ALLOWED_ACTION_SETS: frozenset[frozenset[NCActionType]] = frozenset([
    frozenset(),
    frozenset([NCActionType.DEPOSIT]),
    frozenset([NCActionType.WITHDRAWAL]),
    frozenset([NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.ACQUIRE_AUTHORITY]),
    frozenset([NCActionType.DEPOSIT, NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.DEPOSIT, NCActionType.ACQUIRE_AUTHORITY]),
    frozenset([NCActionType.WITHDRAWAL, NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.WITHDRAWAL, NCActionType.ACQUIRE_AUTHORITY]),
])


def verify_action_list(actions: Sequence[NCAction], *, restrict_dup_actions: bool) -> None:
    """Perform NCAction verifications that do not depend on the tx."""
    if len(actions) > MAX_ACTIONS_LEN:
        raise NCInvalidAction(f'more actions than the max allowed: {len(actions)} > {MAX_ACTIONS_LEN}')

    actions_map: defaultdict[TokenUid, list[NCAction]] = defaultdict(list)
    for action in actions:
        actions_map[action.token_uid].append(action)

    for token_uid, actions_per_token in actions_map.items():
        action_types = {action.type for action in actions_per_token}
        if action_types not in ALLOWED_ACTION_SETS:
            raise NCInvalidAction(f'conflicting actions for token {token_uid.hex()}')
        if restrict_dup_actions and len(action_types) != len(actions_per_token):
            raise NCInvalidAction(f'duplicate actions for token {token_uid.hex()}')
