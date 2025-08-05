#!/bin/bash

# Test script for the HFI1 DMS debugfs interface.
#
# This script tests the session-based functionality of the DMS debugfs
# interface located at /sys/kernel/debug/hfi1/0/dms.
#
# It verifies:
# - Correct command processing and response formatting for the new API.
# - Session isolation between different file descriptors.
# - Error handling for invalid commands and handles.
# - Automatic resource cleanup when a file descriptor is closed.

set -e # Exit immediately if a command exits with a non-zero status.

DMS_PATH="/sys/kernel/debug/hfi1/0/dms"

# --- Helper Functions ---

# Function to send a command and read the response from a specific file descriptor
# Usage: dms_cmd FD "command string"
dms_cmd() {
    local fd="$1"
    local cmd="$2"
    local response

    echo "--------------------------------------------------" >&2
    echo "SESSION (FD $fd) ==> CMD: $cmd" >&2

    # Write command to the debugfs file via the specified file descriptor
    if ! echo "$cmd" >&"$fd"; then
        echo "ERROR: Failed to write command to FD $fd" >&2
        return 1
    fi

    # Read the response back from the same file descriptor
    read -r response <&"$fd"
    echo "SESSION (FD $fd) <== RESP: $response" >&2
    echo "$response" # Return the response for parsing
}

# Function to handle the multi-line response from cq_read
# Usage: dms_cmd_cq_read FD "command string"
dms_cmd_cq_read() {
    local fd="$1"
    local cmd="$2"
    local line

    echo "--------------------------------------------------" >&2
    echo "SESSION (FD $fd) ==> CMD: $cmd" >&2

    if ! echo "$cmd" >&"$fd"; then
        echo "ERROR: Failed to write command to FD $fd" >&2
        return 1
    fi

    # Read the first line of the response
    read -r line <&"$fd"
    echo "SESSION (FD $fd) <== RESP: $line" >&2

    # Check if it's a single-line error response
    if [[ "$line" =~ ^ERROR ]]; then
        echo "$line"
        return 0
    fi

    # Check if it's the expected multi-line header
    if [[ "$line" != "COMPLETIONS" ]]; then
        echo "ERROR: Expected 'COMPLETIONS' or 'ERROR', got '$line'" >&2
        echo "$line" # Propagate unexpected response
        return 1
    fi

    # Loop through completion entries until "END"
    while read -r line <&"$fd"; do
        echo "SESSION (FD $fd) <== RESP: $line" >&2
        if [[ "$line" =~ ^END ]]; then
            # Return the final "END" line for verification
            echo "$line"
            return 0
        fi
        # Could add validation for completion entry format here if needed
    done

    echo "ERROR: Did not find 'END' marker in cq_read response" >&2
    return 1
}

# Function to extract a value from a response string (e.g., "OK handle=1" -> 1)
# Usage: extract_value "response string" "key"
extract_value() {
    local response="$1"
    local key="$2"
    
    if [[ "$response" =~ $key=([0-9a-fxA-FX]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "ERROR: Key '$key' not found in response: $response" >&2
        exit 1
    fi
}

# Function to check if a command response is "OK"
# Usage: check_ok "response" "command name"
check_ok() {
    local response="$1"
    local cmd_name="$2"
    if [[ ! "$response" =~ ^OK ]]; then
        echo "ERROR: Command '$cmd_name' failed with response: $response" >&2
        exit 1
    fi
}

# --- Main Test Logic ---

main() {
    echo "Starting DMS debugfs interface test..."

    if [ ! -w "$DMS_PATH" ]; then
        echo "Error: DMS debugfs path not found or not writable: $DMS_PATH" >&2
        echo "Please ensure the hfi1 module is loaded and you have root privileges." >&2
        exit 1
    fi

    # Open two file descriptors to represent two independent sessions
    exec 3<> "$DMS_PATH"
    exec 4<> "$DMS_PATH"
    echo "Opened two sessions (FD 3 and FD 4)."

    # --- Test Case 1: Basic workflow in Session 1 (FD 3) ---
    echo
    echo "=== TEST CASE 1: Basic Workflow (Session 1 on FD 3) ==="
    
    local resp
    resp=$(dms_cmd 3 "initialize /tmp/socket1")
    check_ok "$resp" "initialize"
    local svc_handle_1=$(extract_value "$resp" "handle")

    resp=$(dms_cmd 3 "key $svc_handle_1")
    check_ok "$resp" "key"
    local client_key_1=$(extract_value "$resp" "key")
    if [[ "$client_key_1" != "$svc_handle_1" ]]; then
        echo "ERROR: Mismatched handle and key: $svc_handle_1 != $client_key_1" >&2
        exit 1
    fi
    echo "Client key matches handle, as expected in mock."

    # Create a second service to get a unique handle ID for the isolation test
    resp=$(dms_cmd 3 "initialize /tmp/socket1.2")
    check_ok "$resp" "initialize"
    local svc_handle_1b=$(extract_value "$resp" "handle")

    resp=$(dms_cmd 3 "command_queue_open $svc_handle_1")
    check_ok "$resp" "command_queue_open"
    local cmdq_id_1=$(extract_value "$resp" "queue_id")

    resp=$(dms_cmd 3 "completion_queue_open $svc_handle_1")
    check_ok "$resp" "completion_queue_open"
    local cq_id_1=$(extract_value "$resp" "queue_id")

    # Test register_dma_buffer
    # register_dma_buffer <cmdq> <cq> <context> <msg_id> <len> <vaddr> <flags>
    resp=$(dms_cmd 3 "register_dma_buffer $cmdq_id_1 $cq_id_1 99 0xABCDEF 4096 0x10000000 0")
    check_ok "$resp" "register_dma_buffer"

    # Test request_rdma_read
    # request_rdma_read <cmdq> <cq> <context> <lid> <client_key> <msg_id> <len> <vaddr> <flags>
    resp=$(dms_cmd 3 "request_rdma_read $cmdq_id_1 $cq_id_1 100 1 $client_key_1 0x5678 1024 0x20000000 0")
    check_ok "$resp" "request_rdma_read"
    
    # Test cq_read. Expect 0 completions from the stub.
    resp=$(dms_cmd_cq_read 3 "cq_read $cq_id_1 16")
    if ! [[ "$resp" =~ END\ 0 ]]; then
        echo "ERROR: Unexpected cq_read response footer: $resp" >&2
        exit 1
    fi

    # Test MR functions
    # mr_open <cmdq> <cq> <context> <len> <vaddr>
    resp=$(dms_cmd 3 "mr_open $cmdq_id_1 $cq_id_1 101 8192 0x30000000")
    check_ok "$resp" "mr_open"
    local mr_handle_1=$(extract_value "$resp" "mr_handle")

    # Test _mr variants (mocked)
    # register_dma_buffer_mr <cmdq> <cq> <context> <msg_id> <len> <mr_handle> <offset>
    resp=$(dms_cmd 3 "register_dma_buffer_mr $cmdq_id_1 $cq_id_1 102 0xFEED 2048 $mr_handle_1 0")
    check_ok "$resp" "register_dma_buffer_mr"
    # request_rdma_read_mr <cmdq> <cq> <context> <lid> <client_key> <msg_id> <len> <mr_handle> <offset>
    resp=$(dms_cmd 3 "request_rdma_read_mr $cmdq_id_1 $cq_id_1 103 1 $client_key_1 0xCAFE 4096 $mr_handle_1 1024")
    check_ok "$resp" "request_rdma_read_mr"

    # mr_close <cmdq> <cq> <context> <mr_handle>
    resp=$(dms_cmd 3 "mr_close $cmdq_id_1 $cq_id_1 104 $mr_handle_1")
    check_ok "$resp" "mr_close"

    # Explicitly close queues
    resp=$(dms_cmd 3 "command_queue_close $cmdq_id_1")
    check_ok "$resp" "command_queue_close"
    resp=$(dms_cmd 3 "completion_queue_close $cq_id_1")
    check_ok "$resp" "completion_queue_close"

    # --- Test Case 2: Session Isolation ---
    echo
    echo "=== TEST CASE 2: Session Isolation (FD 3 vs FD 4) ==="

    # Connect on Session 2 (FD 4)
    resp=$(dms_cmd 4 "initialize /tmp/socket2")
    check_ok "$resp" "initialize"
    local svc_handle_2=$(extract_value "$resp" "handle")

    # Try to use a handle from Session 1 on Session 2 - should fail
    echo "Attempting to use handle $svc_handle_1b (from Session 1) on Session 2. This should fail."
    resp=$(dms_cmd 4 "finalize $svc_handle_1b")
    if ! [[ "$resp" =~ ERROR ]]; then
        echo "FAILURE: Session isolation test failed. Finalize should have returned an error." >&2
        exit 1
    fi
    echo "Success: Command failed as expected."

    # --- Test Case 3: Error Handling ---
    echo
    echo "=== TEST CASE 3: Error Handling ==="
    
    # Finalize Session 1
    resp=$(dms_cmd 3 "finalize $svc_handle_1")
    check_ok "$resp" "finalize"
    resp=$(dms_cmd 3 "finalize $svc_handle_1b")
    check_ok "$resp" "finalize"

    # Try to use the now-invalid handle from Session 1. This should fail.
    echo "Attempting to use finalized handle $svc_handle_1. This should fail."
    resp=$(dms_cmd 3 "command_queue_open $svc_handle_1")
    if ! [[ "$resp" =~ ERROR ]]; then
        echo "FAILURE: Error handling test failed. Using a stale handle should result in an error." >&2
        exit 1
    fi
    echo "Success: Command failed as expected."

    # Test an invalid command
    echo "Attempting to send a malformed command."
    resp=$(dms_cmd 3 "this is not a valid command")
    if ! [[ "$resp" =~ ERROR ]]; then
        echo "FAILURE: Error handling test failed. Malformed command should result in an error." >&2
        exit 1
    fi
    echo "Success: Command failed as expected."

    # --- Test Case 4: Automatic Cleanup on Close ---
    echo
    echo "=== TEST CASE 4: Automatic Cleanup on Close ==="

    # Open a new session on FD 5
    exec 5<> "$DMS_PATH"
    echo "Opened a new session (FD 5)."

    # Create a service and a queue, but do not clean them up
    resp=$(dms_cmd 5 "initialize /tmp/socket3")
    check_ok "$resp" "initialize"
    local svc_handle_3=$(extract_value "$resp" "handle")
    resp=$(dms_cmd 5 "command_queue_open $svc_handle_3")
    check_ok "$resp" "command_queue_open"

    # Close the FD. The kernel module should automatically clean up resources.
    echo "Closing FD 5 without explicit finalize. Kernel should auto-cleanup."
    exec 5>&-
    echo "Session on FD 5 closed. Check kernel logs for auto-cleanup messages."

    # --- Cleanup ---
    echo
    echo "=== CLEANUP ==="
    
    # Finalize the remaining session
    resp=$(dms_cmd 4 "finalize $svc_handle_2")
    check_ok "$resp" "finalize"

    # Close file descriptors
    exec 3>&-
    exec 4>&-
    echo "Closed sessions (FD 3 and FD 4)."
    echo
    echo "DMS debugfs interface test completed successfully!"
}

main
