#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Step-plot encoded byte size vs value for current, LEB128, and length-prefix encodings.

Byte sizes are derived from each encoding's closed-form formula
(`bit_length`-based), so we touch O(transitions) points rather than enumerating
the 2**128 integers in the domain."""

import sys
from typing import Callable

import matplotlib.pyplot as plt
from matplotlib.ticker import FixedFormatter, FixedLocator

MAX_VALUE = 1 << 128  # right edge of the chart
CURRENT_MAX = 1 << 63  # inclusive max of the current encoder
CURRENT_4BYTE_MAX = (1 << 31) - 1


def current_size(value: int) -> int:
    """Bytes used by `output_value_to_bytes` (fixed 4 below 2**31, 8 up to 2**63)."""
    return 4 if value <= CURRENT_4BYTE_MAX else 8


def leb128_size(value: int) -> int:
    """Bytes used by unsigned LEB128 for `value > 0`: ceil(bit_length / 7)."""
    return (value.bit_length() + 6) // 7


def length_prefix_size(value: int) -> int:
    """Bytes used by length-prefix minimal-BE encoding for `value > 0`: 1 + ceil(bit_length / 8)."""
    return 1 + (value.bit_length() + 7) // 8


def step_points(
    encoder: Callable[[int], int],
    transition_bits: list[int],
    max_value: int,
) -> tuple[list[float], list[int]]:
    """(xs, ys) for `step(..., where='post')` over [1, max_value]. `transition_bits` lists the
    bit-widths k where `encoder` changes its output at `2**k`; entries above max_value are dropped.

    xs are cast to float so matplotlib's int64-bound numeric path accepts magnitudes above 2**63."""
    xs_int = sorted({1, max_value, *(1 << k for k in transition_bits if (1 << k) <= max_value)})
    ys = [encoder(x) for x in xs_int]
    return [float(x) for x in xs_int], ys


def main(output_path: str) -> None:
    fig, ax = plt.subplots(figsize=(14, 7))

    # LEB128 changes width at every 7-bit boundary; length-prefix at every 8-bit boundary;
    # current at 2**31 (4 → 8 bytes) and then overflows past 2**63.
    for label, encoder, bits, max_v in [
        ('current', current_size, [31], CURRENT_MAX),
        ('leb128', leb128_size, list(range(7, 129, 7)), MAX_VALUE),
        ('length-prefix', length_prefix_size, list(range(8, 129, 8)), MAX_VALUE),
    ]:
        xs, ys = step_points(encoder, bits, max_v)
        ax.step(xs, ys, where='post', label=label, linewidth=2)

    ax.set_xscale('log', base=2)
    ax.set_xlabel('value (log₂ scale)')
    ax.set_ylabel('encoded byte size')
    ax.set_title('Encoded byte size vs value, by encoding')
    ax.set_xlim(1.0, float(MAX_VALUE))
    ax.set_ylim(0, 20)
    ax.set_yticks(range(0, 21, 5))
    ax.yaxis.set_minor_locator(FixedLocator(range(0, 21)))
    # Default base-2 log labels are 40-digit integers at the far end — replace with 2^N.
    tick_exponents = list(range(0, 129, 16))
    ax.xaxis.set_major_locator(FixedLocator([2.0 ** e for e in tick_exponents]))
    ax.xaxis.set_major_formatter(FixedFormatter([f'$2^{{{e}}}$' for e in tick_exponents]))
    ax.grid(True, which='major', alpha=0.4)
    ax.grid(True, which='minor', alpha=0.15)
    ax.legend()

    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    print(f'wrote {output_path}')


if __name__ == '__main__':
    _, output_path = sys.argv
    main(output_path)
