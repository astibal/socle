# Meter regression tests

Run independently of the proxy application:

```sh
cmake -S tests/meter -B build/meter
cmake --build build/meter
ctest --test-dir build/meter --output-on-failure
```

Requires a C++17 compiler, CMake, and GoogleTest.

`meter::get()` reports bytes per second across four intervals, including the
current interval. During startup its denominator grows with elapsed intervals,
not the number of writes. The default interval is one second; zero is normalized
to one. Bucket boundaries are relative to construction and use `steady_clock`.
A sample expires at the start of its fourth following interval, without requiring
another `update()`. `total()` remains cumulative. `update()` returns the preceding
interval's byte count, not the rate. The explicit timestamp overloads allow tests
without wall-clock sleeps; normal callers keep using `update(bytes)` and `get()`.

The former public scoreboard helpers were implementation details and have no
callers in socle or Smithproxy; they are replaced by private window accounting.
Rebuild consumers when applying this patch: the meter's class layout changes.
