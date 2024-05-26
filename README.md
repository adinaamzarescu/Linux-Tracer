# Kprobe-based Tracer

## Overview

This Linux kernel module leverages Kprobes to monitor specific kernel functions involved in process management, memory allocation, and synchronization. It dynamically captures and logs detailed activity of these functions, tailored to enhance system performance analysis and debugging.

## Features

- **Kernel Function Tracing**: Targets specific kernel functions for monitoring without the need to modify or recompile the kernel.
- **Process Tracking**: Collects data on function calls and memory operations for individual processes.
- **Proc Interface**: Outputs tracing data via a `/proc` file, facilitating easy access and real-time monitoring.
- **Synchronization Primitive Monitoring**: Tracks operations on mutexes and semaphores, providing insights into synchronization behaviors and potential bottlenecks.
- **Memory Management Tracing**: Observes all `kmalloc` and `kfree` activities to help identify memory leaks and allocation patterns.

## Detailed Component Overview

### Data Structures

- **`process_tracing_info`**: Holds tracing data for each monitored process, including the process ID, counts of different function calls, and memory usage statistics.
- **`memory_allocation_record`**: Details each memory allocation, storing the allocation address and size for tracking the lifecycle of kernel memory usage.

### Global Variables and Spinlocks

- **Lists**: Two main lists, `process_tracing_list` and `memory_allocation_list`, store process-specific tracing information and memory allocation records, respectively.
- **Spinlocks**: `proc_list_lock` and `mem_map_lock` protect these lists from concurrent access in multi-threaded environments.

### Detailed Function Explanations

#### Memory Allocation Management Functions

1. **`alloc_memory_map_trace_info(void *allocation_address, size_t allocation_size)`**
   - **Purpose**: Creates a new memory allocation record.
   - **Process**:
     - **Memory Allocation**: Uses `kzalloc` for zero-initialized memory allocation for preventing uninitialized data use.
     - **Initialization**: Sets the record's `allocation_address` and `allocation_size`.
     - **Error Handling**: Logs a warning and returns `NULL` if `kzalloc` fails.

2. **`add_elem_to_memory_map(void *allocation_address, size_t allocation_size)`**
   - **Purpose**: Adds a new memory allocation record to a global list.
   - **Process**:
     - **Record Creation**: Calls `alloc_memory_map_trace_info` to create a new record.
     - **Concurrency Management**: Acquires a spinlock (`mem_map_lock`) to prevent concurrent list access.
     - **List Manipulation**: Adds the record to `memory_allocation_list`.
     - **Error Handling**: Logs an error and returns `-ENOMEM` if the record creation fails.

3. **`remove_elem_from_memory_map(void *kfree_address)`**
   - **Purpose**: Removes a memory allocation record based on the deallocation address.
   - **Process**:
     - **Traversal**: Searches `memory_allocation_list` for the record matching the `kfree_address`.
     - **Record Deletion**: Uses `list_del` to remove the record and `kfree` to free the associated memory.

#### Process Tracing Management Functions

1. **`alloc_process_trace_info(pid_t pid)`**
   - **Purpose**: Allocates and initializes tracing information for a new process.
   - **Process**:
     - **Memory Allocation**: Uses `kzalloc` for zero-initialized memory.
     - **Initialization**: Stores the `pid` and initializes function call and memory usage counters.
     - **Error Handling**: Logs a warning if memory allocation fails.

2. **`add_elem_to_process_tracing_list(pid_t pid)`**
   - **Purpose**: Adds a process's tracing information to the global list.
   - **Process**:
     - **Information Creation**: Creates a new `process_tracing_info` record for the PID.
     - **Concurrency Management**: Uses `proc_list_lock` spinlock for safe access.
     - **List Manipulation**: Adds the new trace info to `process_tracing_list`.

3. **`remove_elem_from_process_tracing_list(pid_t pid)`**
   - **Purpose**: Removes a process's tracing information from the list.
   - **Process**:
     - **List Traversal and Deletion**: Searches for and deletes the corresponding record.
     - **Concurrency Management**: Ensures deletion is protected by `proc_list_lock`.

#### Event Recording and Proc File Management

- **`record_tracer_event(pid_t pid, int function_key, size_t size, EventType event_type)`**
  - **Purpose**: Logs function calls or memory operations for specified processes.
  - **Process**: Updates either function call count or memory usage in the process's record.

- **`tracer_print(struct seq_file *seq_output, void *data)`**
  - **Purpose**: Outputs all collected tracing data to a sequence file.
  - **Process**: Prints headers and then iterates over `process_tracing_list` to print each process's data.

#### Kretprobe Handlers

- **Entry Handlers**: Capture parameters from CPU registers.
- **Return Handlers**: Capture return values and modify tracing records based on outcomes.

### Initialization and Cleanup

- **`tracer_init(void)`**: Sets up the module, registers the device, creates a proc file, and registers kretprobes.
- **`tracer_exit(void)`**: Cleans up by deregistering the device, removing the proc file, and unregistering all kretprobes.

## Resources

1. **Linux Kernel Kprobes**:
   - [Linux Kernel Kprobes Documentation](https://www.kernel.org/doc/Documentation/kprobes.txt)
   - [Kprobes Sample Code](https://elixir.bootlin.com/linux/latest/source/samples/kprobes)

2. **Detailed Kprobes Guides**:
   - [Dynamic Probing of Kernel Code with Kprobes](https://www.kernel.org/doc/html/latest/trace/kprobes.html)
   - [LWN.net: Kprobes - A Kernel Debugger](https://lwn.net/Articles/132196/)
