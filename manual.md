
./profiler -pid 1234 -duration 30s -output profile.folded


./profiler -pid 1234 -duration 30s -output profile.jfr -file-type jfr


./profiler -pid 1234 -duration 30s -output profile.pb.gz -file-type pprof

./ebpf-profiler -enable-cuda -cuda-binary libcuda_usdt_full.so  -pid 1234 -duration 30s   -output profile.folded

./profiler -enable-cuda -enable-time=false -pid 1234 -duration 30s -output result.folded




# 容器pid
-v /proc:/host/proc:ro
./ebpf-profiler  -host-proc=/host/proc 