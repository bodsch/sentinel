// Separate module: the benchmark harness is developer tooling and must not pull
// any dependency into the main sentinel module. It uses only the standard
// library, so this file has no require block.
module bodsch.me/sentinel/bench

go 1.26
