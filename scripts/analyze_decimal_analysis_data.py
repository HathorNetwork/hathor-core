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

import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.axes import Axes

from hathor.transaction.exceptions import InvalidOutputValue
from hathor.transaction.util import output_value_to_bytes
from hathorlib.utils.leb128 import encode_unsigned

BYTES_PER_MB = 1024 * 1024

MAX_LENGTH_PREFIX_VALUE = 2**256 - 1
MAX_LENGTH_PREFIX_PAYLOAD_BYTES = 32


def encode_length_prefix_minimal_be(value: int) -> bytes:
    """
    Canonical encoding:

        [length: u8][minimal big-endian unsigned integer bytes]

    Rules:
    - value must be strictly positive
    - positive values are encoded with the shortest possible big-endian byte sequence
    - max value is 2**256 - 1
    """
    if not isinstance(value, int):
        raise TypeError("value must be an int")

    if value <= 0:
        raise ValueError("value must be strictly positive")

    if value > MAX_LENGTH_PREFIX_VALUE:
        raise ValueError(f"value is too big; max possible value is 2**256 - 1, got: {value}")

    payload = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")

    assert 1 <= len(payload) <= MAX_LENGTH_PREFIX_PAYLOAD_BYTES
    assert payload[0] != 0

    return bytes([len(payload)]) + payload


def decode_length_prefix_minimal_be(data: bytes | bytearray | memoryview) -> tuple[int, int]:
    """
    Decodes one canonical length-prefix value.

    Returns:

        (value, bytes_consumed)
    """
    data = bytes(data)

    if len(data) < 1:
        raise ValueError("missing length byte")

    length = data[0]

    if length == 0:
        raise ValueError("value must be strictly positive")

    if length > MAX_LENGTH_PREFIX_PAYLOAD_BYTES:
        raise ValueError(f"invalid length: {length}; max is {MAX_LENGTH_PREFIX_PAYLOAD_BYTES}")

    if len(data) < 1 + length:
        raise ValueError("not enough bytes for encoded value")

    payload = data[1 : 1 + length]

    if payload[0] == 0:
        raise ValueError("non-canonical encoding: leading zero byte")

    value = int.from_bytes(payload, byteorder="big")

    assert 1 <= value <= MAX_LENGTH_PREFIX_VALUE

    return value, 1 + length


VALUE_SEPARATOR = ';'
BLOCK_TYPE = 'b'
TX_TYPE = 't'

OVERFLOW_LABEL = 'overflow'

EncoderFn = Callable[[int], int | None]


@lru_cache(maxsize=2_000_000)
def encoded_size_current(value: int) -> int | None:
    """Byte size of `output_value_to_bytes(value)`, or None on overflow."""
    try:
        return len(output_value_to_bytes(value))
    except InvalidOutputValue:
        return None


@lru_cache(maxsize=2_000_000)
def encoded_size_leb128(value: int) -> int | None:
    """Byte size of the unsigned-LEB128 encoding of `value`, or None on failure."""
    try:
        return len(encode_unsigned(value))
    except ValueError:
        return None


@lru_cache(maxsize=2_000_000)
def encoded_size_length_prefix(value: int) -> int | None:
    """Byte size of the canonical length-prefix minimal-BE encoding, or None on failure."""
    try:
        return len(encode_length_prefix_minimal_be(value))
    except (ValueError, TypeError):
        return None


@dataclass(slots=True, frozen=True)
class Variant:
    """One point on the (decimals, encoding) grid we sweep over."""
    label: str
    multiplier: int
    encoder: EncoderFn


# Baseline is 2-decimal `current` (multiplier=1, output_value_to_bytes). The dataset's values are
# integers at 2-decimal precision, so multiplier=10**6 simulates 8 decimals (2 + 6), etc.
VARIANTS: tuple[Variant, ...] = (
    Variant('2 dec (current)', 1, encoded_size_current),
    Variant('8 dec (current)', 10 ** 6, encoded_size_current),
    Variant('18 dec (current)', 10 ** 16, encoded_size_current),
    Variant('8 dec (leb128)', 10 ** 6, encoded_size_leb128),
    Variant('18 dec (leb128)', 10 ** 16, encoded_size_leb128),
    Variant('8 dec (length-prefix)', 10 ** 6, encoded_size_length_prefix),
    Variant('18 dec (length-prefix)', 10 ** 16, encoded_size_length_prefix),
)

# Right-inclusive bins for `pd.cut`: (-1, 0] => '0', (0, 1] => '1', …, (50, inf) => '51+'.
BUCKET_BINS: list[float] = [-1, 0, 1, 2, 3, 4, 5, 10, 50, float('inf')]
BUCKET_LABELS: list[str] = ['0', '1', '2', '3', '4', '5', '6-10', '11-50', '51+']


def parse_values(raw: str) -> list[int]:
    """Parse a semicolon-separated cell into a list of ints. Empty cell yields []."""
    if not raw:
        return []
    return [int(v) for v in raw.split(VALUE_SEPARATOR)]


def encoded_size_label(value: int, variant: Variant) -> str:
    """Byte-size label for `value` under `variant`, or 'overflow' if it can't be encoded."""
    size = variant.encoder(value * variant.multiplier)
    return OVERFLOW_LABEL if size is None else str(size)


def byte_size_delta(value: int, variant: Variant) -> int:
    """Change in encoded size when switching from baseline (current encoder, 2 dec) to `variant`.
    Overflow on either side ⇒ 0 (treat overflowing values as keeping their original encoded size)."""
    old = encoded_size_current(value)
    new = variant.encoder(value * variant.multiplier)
    if old is None or new is None:
        return 0
    return new - old


def sum_byte_size_delta(value_lists: pd.Series, variant: Variant) -> int:
    """Sum of `byte_size_delta` across all values in the given lists."""
    if variant.multiplier == 1 and variant.encoder is encoded_size_current:
        return 0
    flat = value_lists.explode().dropna().map(int)
    return int(flat.map(lambda v, var=variant: byte_size_delta(v, var)).sum())


def size_with_variant(group_df: pd.DataFrame, variant: Variant) -> int:
    """Total stored bytes for `group_df` if all values were re-encoded under `variant`."""
    base = int(group_df['size'].sum())
    outputs_delta = sum_byte_size_delta(group_df['output_values_list'], variant)
    nc_delta = sum_byte_size_delta(group_df['nc_action_values_list'], variant)
    return base + outputs_delta + nc_delta


def sum_encoded_output_size(value_lists: pd.Series, variant: Variant) -> int:
    """Sum of encoded byte sizes for every value in `value_lists` under `variant`.
    Overflow falls back to the baseline encoded size, mirroring `byte_size_delta` so the
    absolute size and the delta vs. baseline stay consistent."""
    flat = value_lists.explode().dropna().map(int)

    def encoded_size(v: int) -> int:
        size = variant.encoder(v * variant.multiplier)
        if size is None:
            return encoded_size_current(v) or 0
        return size

    return int(flat.map(encoded_size).sum())


def format_size(size: int, baseline: int | None) -> str:
    """Render a size in MB; if `baseline` is given, append the signed percent change vs baseline."""
    line = f'{size / BYTES_PER_MB:.2f} MB'
    if baseline is not None and baseline != 0:
        pct = (size - baseline) / baseline * 100
        line += f' ({pct:+.2f}%)'
    return line


def byte_size_dists_by_variant(value_lists: pd.Series) -> dict[str, pd.Series]:
    """Distribution of encoded byte-size labels per variant in VARIANTS."""
    flat = value_lists.explode().dropna().map(int)
    return {
        variant.label: flat.map(lambda v, var=variant: encoded_size_label(v, var)).value_counts()
        for variant in VARIANTS
    }


def sort_value_size_series(series: pd.Series) -> pd.Series:
    """Sort byte-size labels: numeric ascending, then 'overflow' last."""
    keys = list(series.index)
    numeric = sorted((k for k in keys if k != OVERFLOW_LABEL), key=int)
    ordered = list(numeric) + ([OVERFLOW_LABEL] if OVERFLOW_LABEL in keys else [])
    return series.reindex(ordered)


def bucketed_counts(values: pd.Series) -> pd.Series:
    """Roll a series of integers up into BUCKETS — for long-tailed distributions."""
    binned = pd.cut(values, bins=BUCKET_BINS, labels=BUCKET_LABELS)
    return binned.value_counts().reindex(BUCKET_LABELS, fill_value=0)


def draw_bar(ax: Axes, series: pd.Series, title: str, xlabel: str) -> None:
    """Render one bar chart from a Series whose index labels the bars and values are bar heights."""
    labels = [str(i) for i in series.index]
    heights = [int(v) for v in series.values]
    bars = ax.bar(labels, heights)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel('count')
    ax.bar_label(bars, padding=2, fontsize=8)


def save_chart(output_dir: Path, filename: str, series: pd.Series, title: str, xlabel: str) -> None:
    """Render one distribution to its own PNG file."""
    fig, ax = plt.subplots(figsize=(8, 5))
    draw_bar(ax, series, title, xlabel)
    fig.tight_layout()
    path = output_dir / filename
    fig.savefig(path)
    plt.close(fig)
    print(f'wrote {path}')


def save_variant_chart(
    output_dir: Path,
    filename: str,
    series_by_variant: dict[str, pd.Series],
    title: str,
    xlabel: str,
) -> None:
    """Render one PNG with four rows: baseline on its own row, then one row per encoder
    (current / leb128 / length-prefix), with 8-dec on the left and 18-dec on the right."""
    fig = plt.figure(figsize=(12, 20), constrained_layout=True)
    gs = fig.add_gridspec(4, 2)
    fig.suptitle(title)
    items = list(series_by_variant.items())
    baseline_label, baseline_series = items[0]
    ax_baseline = fig.add_subplot(gs[0, :])
    draw_bar(ax_baseline, sort_value_size_series(baseline_series), baseline_label, xlabel)
    for row, pair in enumerate(zip(items[1::2], items[2::2]), start=1):
        for col, (variant_label, series) in enumerate(pair):
            ax = fig.add_subplot(gs[row, col])
            draw_bar(ax, sort_value_size_series(series), variant_label, xlabel)
    path = output_dir / filename
    fig.savefig(path)
    plt.close(fig)
    print(f'wrote {path}')


def main(input_path: str, output_dir: str) -> None:
    out_dir = Path(output_dir)
    # Read everything as string so chunked dtype inference can't turn single-int cells into ints in
    # `output_values`/`nc_action_values`; `keep_default_na=False` preserves empty cells as ''.
    df = pd.read_csv(input_path, dtype=str, keep_default_na=False)
    df['size'] = df['size'].astype(int)
    df['output_values_list'] = df['output_values'].apply(parse_values)
    df['nc_action_values_list'] = df['nc_action_values'].apply(parse_values)
    df['output_count'] = df['output_values_list'].map(len)
    df['nc_action_count'] = df['nc_action_values_list'].map(len)

    blocks_df = df[df['type'] == BLOCK_TYPE]
    txs_df = df[df['type'] == TX_TYPE]

    baseline = VARIANTS[0]
    baseline_total = size_with_variant(df, baseline)
    baseline_blocks = size_with_variant(blocks_df, baseline)
    baseline_txs = size_with_variant(txs_df, baseline)
    baseline_total_outputs = sum_encoded_output_size(df['output_values_list'], baseline)
    baseline_blocks_outputs = sum_encoded_output_size(blocks_df['output_values_list'], baseline)
    baseline_txs_outputs = sum_encoded_output_size(txs_df['output_values_list'], baseline)
    # Authority outputs and GRANT_AUTHORITY / ACQUIRE_AUTHORITY NC actions encode their
    # bitfield via the same `output_value_to_bytes` path but are filtered out by the gen
    # script. The encoder swap applies to those bytes too, so non-baseline totals are
    # biased: LEB128 wins are understated, length-prefix overhead is overstated.
    print('note: totals exclude authority output values and authority NC action amounts')
    for variant in VARIANTS:
        # 18 + current is infeasible: most scaled values overflow the 2^63 cap, and the
        # `byte_size_delta` overflow fallback returns 0, so the totals don't reflect that.
        if variant.encoder is encoded_size_current and variant.multiplier == 10 ** 16:
            continue
        is_baseline = variant is baseline
        total = size_with_variant(df, variant)
        blocks = size_with_variant(blocks_df, variant)
        txs = size_with_variant(txs_df, variant)
        total_outputs = sum_encoded_output_size(df['output_values_list'], variant)
        blocks_outputs = sum_encoded_output_size(blocks_df['output_values_list'], variant)
        txs_outputs = sum_encoded_output_size(txs_df['output_values_list'], variant)
        print(f'=== {variant.label} ===')
        print(f'total size: {format_size(total, None if is_baseline else baseline_total)}')
        print(f'blocks size: {format_size(blocks, None if is_baseline else baseline_blocks)}')
        print(f'transactions size: {format_size(txs, None if is_baseline else baseline_txs)}')
        print(f'total outputs size: {format_size(total_outputs, None if is_baseline else baseline_total_outputs)}')
        print(f'block outputs size: {format_size(blocks_outputs, None if is_baseline else baseline_blocks_outputs)}')
        print(f'transactions outputs size: {format_size(txs_outputs, None if is_baseline else baseline_txs_outputs)}')

    assert (blocks_df['output_count'] == 1).all(), (
        f'expected every block to have exactly 1 output, '
        f'got {blocks_df["output_count"].value_counts().to_dict()}'
    )
    print('all blocks have 1 output')

    outputs_count_dist = bucketed_counts(txs_df['output_count'])
    nc_actions_count_dist = txs_df['nc_action_count'].value_counts().sort_index()
    output_value_size_dists = byte_size_dists_by_variant(txs_df['output_values_list'])
    nc_action_value_size_dists = byte_size_dists_by_variant(txs_df['nc_action_values_list'])

    save_chart(out_dir, 'outputs_count_txs.png', outputs_count_dist,
               'number of outputs (transactions)', 'outputs')
    save_chart(out_dir, 'nc_actions_count_txs.png', nc_actions_count_dist,
               'number of nc actions (transactions)', 'nc actions')
    save_variant_chart(out_dir, 'output_value_size_txs.png', output_value_size_dists,
                       'output value byte size (transactions)', 'bytes')
    save_variant_chart(out_dir, 'nc_action_value_size_txs.png', nc_action_value_size_dists,
                       'nc action value byte size (transactions)', 'bytes')


if __name__ == '__main__':
    _, input_path, output_dir = sys.argv
    main(input_path, output_dir)
