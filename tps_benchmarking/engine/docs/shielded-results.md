# Shielded measurement results (CP-10)

_K=30 measured (+5 warm-up) per row, 1-tip-transparent chain (tips≈1), 64-bit unless noted, single-thread in-process node._

### 1. Transparent vs shielded (I1 O2)

| workload | acc | TPS | S1 µs | S3S4 µs | S5 µs | S6 µs | total µs | size B |
|---|---|---|---|---|---|---|---|---|
| 1-tip-transparent I1 O2 @64b | 30/30 | **177** | 218 | 1807 | 1594 | 1924 | 5643 | 291 |
| amount-shielded I1 O2 @64b | 30/30 | **35** | 410 | 21714 | 2677 | 3324 | 28272 | 10570 |
| full-shielded I1 O2 @64b | 30/30 | **36** | 386 | 21386 | 2386 | 3510 | 27812 | 10772 |

### 2. Range-proof bit-width (full-shielded I1 O2)

| workload | acc | TPS | S1 µs | S3S4 µs | S5 µs | S6 µs | total µs | size B |
|---|---|---|---|---|---|---|---|---|
| full-shielded I1 O2 @40b | 30/30 | **56** | 299 | 13034 | 1730 | 2727 | 17884 | 7058 |
| full-shielded I1 O2 @52b | 30/30 | **41** | 350 | 17650 | 2720 | 3610 | 24459 | 8980 |
| full-shielded I1 O2 @64b | 30/30 | **41** | 297 | 19229 | 1950 | 2803 | 24395 | 10772 |

### 3. Shielded output count (full-shielded I1, 64-bit)

| workload | acc | TPS | S1 µs | S3S4 µs | S5 µs | S6 µs | total µs | size B |
|---|---|---|---|---|---|---|---|---|
| full-shielded I1 O2 @64b | 30/30 | **43** | 302 | 18129 | 1880 | 2784 | 23206 | 10772 |
| full-shielded I1 O4 @64b | 30/30 | **27** | 320 | 31405 | 1865 | 2845 | 36548 | 21308 |
| full-shielded I1 O8 @64b | 30/30 | **14** | 494 | 66585 | 2325 | 3661 | 73177 | 42380 |
