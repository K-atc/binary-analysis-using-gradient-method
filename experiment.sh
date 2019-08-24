#!/bin/sh

get_base_dir() {
    experiment_name=$1
    date=$(date +%Y%m%d)
    host_name=$(hostname)
    ncpu=$(grep processor /proc/cpuinfo | wc -l)
    echo "result/${experiment_name}/${date}/${host_name}_vcpu_${ncpu}/"
}

save_host_info() {
    base_dir=$1
    mkdir -p $base_dir
    cp /etc/hostname $base_dir
    cp /proc/cpuinfo $base_dir
    cp /etc/os-release $base_dir
}

solve_file_with_init() {
    init=$2
    save_dir="$1/$init/"
    mkdir -p $save_dir
    TIME=on ./solve.sh solver/solve-file.sage --magic --init $init 2>&1 | tee $save_dir/solve.log
}

source solver/solve-file.env
base_dir=$(get_base_dir "solve_file_with_init")
echo "[*] Result is saved to $base_dir"

save_host_info $base_dir

solve_file_with_init $base_dir "AAAAAAAA"
solve_file_with_init $base_dir "ustarssz"

echo "[*] Finished!"