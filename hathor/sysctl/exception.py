# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

class SysctlException(Exception):
    pass


class SysctlEntryNotFound(SysctlException):
    pass


class SysctlReadOnlyEntry(SysctlException):
    pass


class SysctlWriteOnlyEntry(SysctlException):
    pass


class SysctlRunnerException(SysctlException):
    pass
