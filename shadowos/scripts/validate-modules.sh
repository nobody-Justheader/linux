#!/bin/bash
# ShadowOS Module Validation Script
# Compiles each module individually to catch compilation errors

set -uo pipefail

MODULES_DIR="/usr/src/shadowos-modules"
KERNEL_VERSION=$(uname -r)

echo "=== ShadowOS Module Validation ==="
echo "Kernel: $KERNEL_VERSION"
echo ""

FAILED=0
PASSED=0
FAILED_MODULES=""

# Create a Makefile for individual module testing
create_test_makefile() {
    local module_name=$1
    local module_dir=$2
    cat > /tmp/test_module_Makefile << EOF
KERNELDIR := /lib/modules/$KERNEL_VERSION/build
PWD := \$(shell pwd)
obj-m := ${module_name}.o
EXTRA_CFLAGS := -I${MODULES_DIR}/include

all:
	\$(MAKE) -C \$(KERNELDIR) M=\$(PWD) modules

clean:
	\$(MAKE) -C \$(KERNELDIR) M=\$(PWD) clean
EOF
}

# Test a single module
test_module() {
    local module_path=$1
    local module_name=$(basename "$module_path" .c)
    local module_dir=$(dirname "$module_path")
    
    echo -n "Testing $module_name... "
    
    # Create temp dir and copy source
    local tmp_dir="/tmp/mod_test_$$_$module_name"
    mkdir -p "$tmp_dir"
    cp "$module_path" "$tmp_dir/"
    
    # Create test Makefile
    create_test_makefile "$module_name" "$module_dir"
    cp /tmp/test_module_Makefile "$tmp_dir/Makefile"
    
    # Try to compile
    cd "$tmp_dir"
    if make 2>&1 > /tmp/compile_output_$module_name.txt; then
        echo "PASS"
        ((PASSED++))
    else
        echo "FAIL"
        ((FAILED++))
        FAILED_MODULES="$FAILED_MODULES $module_name"
        echo "--- Errors for $module_name ---"
        grep -E "error:|undefined|implicit" /tmp/compile_output_$module_name.txt | head -20
        echo "---"
    fi
    
    # Cleanup
    rm -rf "$tmp_dir"
    cd - > /dev/null
}

echo "=== Testing net/shadowos modules ==="
for module in "$MODULES_DIR"/net/shadowos/*.c; do
    [[ -f "$module" ]] || continue
    [[ "$(basename $module)" == *.mod.c ]] && continue
    test_module "$module"
done

echo ""
echo "=== Testing security/shadowos modules ==="
for module in "$MODULES_DIR"/security/shadowos/*.c; do
    [[ -f "$module" ]] || continue
    [[ "$(basename $module)" == *.mod.c ]] && continue
    test_module "$module"
done

echo ""
echo "=== Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
if [[ $FAILED -gt 0 ]]; then
    echo "Failed modules:$FAILED_MODULES"
    exit 1
fi
exit 0
