#!/usr/bin/env bash
# Run this FIRST on the LinuxONE instance. It reports what the machine can do, so we
# only claim features we actually have. Paste the output into the team chat.
#   bash scripts/check_instance.sh

echo "== Architecture (expect s390x) ==";  uname -m
echo; echo "== OS ==";                       grep -E '^(NAME|VERSION)=' /etc/os-release
echo; echo "== CPUs / memory ==";            nproc; free -h | head -2
echo; echo "== Disk ==";                     df -h ~ | tail -1

echo; echo "== Machine type ==";
TYPE=$(grep -m1 '^Type:' /proc/sysinfo 2>/dev/null | awk '{print $2}')
case "$TYPE" in
  8561|8562) GEN="z15 / LinuxONE III: vector (VXE) acceleration for llama.cpp; no on-chip AI accelerator" ;;
  3931|3932) GEN="z16 / LinuxONE 4: Telum AI accelerator exists on the chip (check zDNN below)" ;;
  9175|9176) GEN="z17 / LinuxONE 5: Telum II AI accelerator exists on the chip (check zDNN below)" ;;
  *)         GEN="unknown type '$TYPE': ask the organisers" ;;
esac
echo "Type $TYPE -> $GEN"

echo; echo "== AI accelerator library (zDNN) ==";
ls /usr/lib*/libzdnn* /usr/lib/*/libzdnn* 2>/dev/null || echo "libzdnn not found (accelerator not usable from our code yet)"

echo; echo "== Crypto instructions (CPACF) ==";
grep -m1 -o 'msa[0-9]*' /proc/cpuinfo >/dev/null && echo "CPU reports MSA (CPACF) crypto features:" && grep -m1 '^features' /proc/cpuinfo
command -v icainfo >/dev/null && icainfo | head -20 || echo "(install libica-utils and run 'icainfo' for detail)"

echo; echo "== Secure Execution (confidential computing) ==";
if [ -f /sys/firmware/uv/prot_virt_guest ]; then
  echo "prot_virt_guest = $(cat /sys/firmware/uv/prot_virt_guest)  (1 = this VM runs under Secure Execution)"
else
  echo "Not a Secure Execution guest (do not claim it in the pitch; present as design intent)"
fi

echo; echo "== Tools ==";
for t in python3 git cmake gcc docker podman; do printf "%-8s %s\n" "$t" "$(command -v $t || echo MISSING)"; done
python3 --version
