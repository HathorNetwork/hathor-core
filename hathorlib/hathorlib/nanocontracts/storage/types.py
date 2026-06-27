# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Any


class DeletedKeyType:
    pass


# Placeholder to mark a key as deleted in a dict.
DeletedKey = DeletedKeyType()

# Sentinel value to differentiate where a user has provided a default value or not.
# Since _NOT_PROVIDED is a unique object, it is guaranteed not to be equal to any other value.
_NOT_PROVIDED: Any = object()
