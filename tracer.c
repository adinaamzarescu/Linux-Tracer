// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Adina-Maria Amzarescu, 343C3
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include "tracer.h"

#define PROCFS_TRACER_READ	"tracer"

#define NUM_FUNCTIONS_RECORDED 7
#define NUM_MEMORY_OPS_VALUES 2
#define MAX_KRETPROBE_ACTIVE 64
#define BUFFER_SIZE (4096 * 4)

// Headers for the columns of the output data
#define HEADER_PID "PID"
#define HEADER_KMALLOC "kmalloc"
#define HEADER_KFREE "kfree"
#define HEADER_KMALLOC_MEM "kmalloc_mem"
#define HEADER_KFREE_MEM "kfree_mem"
#define HEADER_SCHED "sched"
#define HEADER_UP "up"
#define HEADER_DOWN "down"
#define HEADER_LOCK "lock"
#define HEADER_UNLOCK "unlock"

// Names of the functions to probe
#define KMALLOC_FUNC_NAME "__kmalloc"
#define KFREE_FUNC_NAME "kfree"
#define SCHED_FUNC_NAME "schedule"
#define UP_FUNC_NAME "up"
#define DOWN_FUNC_NAME "down_interruptible"
#define LOCK_FUNC_NAME "mutex_lock_nested"
#define UNLOCK_FUNC_NAME "mutex_unlock"
#define EXIT_FUNC_NAME "do_exit"

// Spinlocks for protecting the process and memory maps from concurrent access
static DEFINE_RAW_SPINLOCK(proc_list_lock);
static DEFINE_RAW_SPINLOCK(mem_map_lock);

// Enumerations to specify types of events and node types in lists
typedef enum EventTypes {
	RECORD_CALL = 0,
	RECORD_MEMORY_ALLOCATION = 1
} EventType;

typedef enum NodeTypes {
	PROCESS_NODE = 1,
	MEMORY_MAP_NODE = 2
} NodeType;

// Keys for indexing function call counts and memory usage
typedef enum FunctionKeys {
	KMALLOC_KEY = 0,
	KFREE_KEY,
	SCHED_KEY,
	UP_KEY,
	DOWN_KEY,
	LOCK_KEY,
	UNLOCK_KEY,
	NUM_KEYS
} FunctionKey;

// Error codes for the module
typedef enum {
	BASE_ERROR_CODE = -1
} ErrorCode;

// Structures to store tracing information per process and per memory allocation
struct process_tracing_info {
	pid_t pid;
	int function_call_count[NUM_FUNCTIONS_RECORDED];
	size_t memory_usage[NUM_MEMORY_OPS_VALUES];
	struct list_head list;
};

struct memory_allocation_record {
	void *allocation_address;
	size_t allocation_size;
	struct list_head list;
};

struct kmalloc_probe_data {
	size_t allocation_size;
};

// Lists to hold all process and memory allocation records
LIST_HEAD(process_tracing_list);
LIST_HEAD(memory_allocation_list);

// Proc entry for accessing the tracer data
struct proc_dir_entry *proc_tracing_info_entry;

// Utility functions for adding and removing elements from lists
bool compare(void *entry, void *key, NodeType type);
static struct memory_allocation_record *alloc_memory_map_trace_info(void *allocation_address, size_t allocation_size);
static int add_elem_to_memory_map(void *allocation_address, size_t allocation_size);
static struct process_tracing_info *alloc_process_trace_info(pid_t pid);
static void add_elem_to_process_tracing_list(pid_t pid);
static void remove_elem_from_process_tracing_list(pid_t pid);

// Functions for printing tracer data to a sequence file
static void print_tracing_headers(struct seq_file *seq_output);
static void print_int_data(struct seq_file *seq_output, int data);
static void print_size_data(struct seq_file *seq_output, size_t data);
static void print_process_trace_info_data(struct seq_file *seq_output, struct process_tracing_info *trace_info);
static int tracer_print(struct seq_file *seq_output, void *data);

// Event recording function for both call and memory allocation events
static void record_tracer_event(pid_t pid, int function_key, size_t size, EventType event_type);

// Functions for removing a memory trace info element from the list
static void remove_memory_trace_info(struct list_head *runner, struct memory_allocation_record *trace_info);
static int remove_elem_from_memory_map(void *kfree_address);

// Initialization and exit functions for the kernel module
static int register_probe(struct kretprobe *probe, const char *func_name);
static int tracer_init(void);
static void tracer_exit(void);

// Kretprobe handler functions for kernel functions to monitor
static int handle_kfree_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_kmalloc_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_kmalloc_return(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_schedule_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_down_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_up_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_mutex_lock_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_mutex_unlock_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);
static int handle_process_exit(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs);

// IOCTL command handling and file operations for the tracer
static long handle_ioctl_commands(struct file *file, unsigned int ioctl_cmd, unsigned long ioctl_arg);
static int proc_file_open(struct inode *inode, struct file *file);


static const struct file_operations tracer_file_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = handle_ioctl_commands
};

static struct kretprobe kfree_probe = {
	.entry_handler = handle_kfree_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe kmalloc_probe = {
	.entry_handler	= handle_kmalloc_entry,
	.handler		= handle_kmalloc_return,
	.maxactive		= MAX_KRETPROBE_ACTIVE,
	.data_size		= sizeof(struct kmalloc_probe_data),
};

static struct kretprobe schedule_probe = {
	.entry_handler = handle_schedule_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe down_probe = {
	.entry_handler = handle_down_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe up_probe = {
	.entry_handler = handle_up_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe mutex_lock_probe = {
	.entry_handler = handle_mutex_lock_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe mutex_unlock_probe = {
	.entry_handler = handle_mutex_unlock_entry,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

static struct kretprobe process_exit_probe = {
	.entry_handler = handle_process_exit,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// Array of all kretprobes
static struct kretprobe *all_kretprobes[] = {
	&kmalloc_probe,
	&kfree_probe,
	&schedule_probe,
	&up_probe,
	&down_probe,
	&mutex_lock_probe,
	&mutex_unlock_probe,
	&process_exit_probe
};

#define NUM_KRETPROBES (sizeof(all_kretprobes) / sizeof(all_kretprobes[0]))

// File operations for the tracer's proc entry
static const struct proc_ops tracer_proc_ops = {
	.proc_open		= proc_file_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

// Miscellaneous device for interacting with the tracer
struct miscdevice tracer_misc_device = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_file_ops,
};


/**
 * alloc_memory_map_trace_info() - Allocate and initialize a memory allocation record
 * @allocation_address: Pointer to the starting address of the memory allocation.
 * @allocation_size: The size of the memory allocation.
 *
 * This function handles creating a memory allocation record,
 * used for tracing and analyzing memory usage linked to kernel functions.
 * If allocation of the record fails, it returns NULL.
 *
 * Return: Pointer to the memory_allocation_record structure or NULL if the allocation fails.
 */

static struct memory_allocation_record *alloc_memory_map_trace_info(void *allocation_address, size_t allocation_size)
{
	// Allocate memory for the record with atomic context to avoid sleeping
	struct memory_allocation_record *trace_info = kzalloc(sizeof(*trace_info), GFP_ATOMIC);

	if (!trace_info) {
		pr_warn("Failed to allocate memory for memory_allocation_record\n");
		return NULL;
	}

	// Set the allocation address and size in the record
	trace_info->allocation_address = allocation_address;
	trace_info->allocation_size = allocation_size;

	return trace_info;
}


/**
 * add_elem_to_memory_map() - Adds a memory allocation record to a global list
 * @allocation_address: Memory allocation's starting address.
 * @allocation_size: Size of the memory allocation.
 *
 * This function adds a memory allocation record to the global tracing list after
 * creating it. If the allocation fails, it returns an error. The function ensures
 * thread safety by locking the list and disabling interrupts during the operation.
 *
 * Return: 0 on success, -ENOMEM on allocation failure.
 */
static int add_elem_to_memory_map(void *allocation_address, size_t allocation_size)
{
	unsigned long flags;

	// Allocate a new memory allocation record
	struct memory_allocation_record *trace_info = alloc_memory_map_trace_info(allocation_address, allocation_size);

	if (!trace_info) {
		pr_err("Failed to allocate memory_allocation_record\n");
		return -ENOMEM;
	}

	// Lock the list and disable interrupts to protect the list manipulation
	raw_spin_lock_irqsave(&mem_map_lock, flags);

	// Add the new record to the list
	list_add(&trace_info->list, &memory_allocation_list);

	// Unlock the list and restore interrupts
	raw_spin_unlock_irqrestore(&mem_map_lock, flags);

	return 0;
}

/**
 * alloc_process_trace_info() - Allocates a tracing information structure for a process
 * @pid: Process ID for which tracing information is to be allocated.
 *
 * This function allocates memory for a process tracing information structure.
 * It stores the provided PID in the allocated structure.
 * If memory allocation fails, it logs an error and returns NULL.
 *
 * Return: Pointer to the allocated process_tracing_info structure, or NULL if allocation fails.
 */
static struct process_tracing_info *alloc_process_trace_info(pid_t pid)
{
	// Allocate memory for the process tracing information structure
	struct process_tracing_info *trace_info = kzalloc(sizeof(*trace_info), GFP_ATOMIC);

	if (!trace_info) {
		pr_err("Failed to allocate process trace_info for PID %d\n", pid);
		return NULL;
	}

	// Store the PID in the tracing info structure
	trace_info->pid = pid;

	return trace_info;
}

/**
 * add_elem_to_process_tracing_list() - Adds a process tracing record to a list
 * @pid: Process ID to track.
 *
 * This function records process activities by adding tracing info for a given PID to a global list.
 * It secures access to the list with locks during the update. If unable to allocate the needed
 * memory, it logs an error.
 */
static void add_elem_to_process_tracing_list(pid_t pid)
{
	unsigned long flags;

	// Allocate tracing information for the given PID
	struct process_tracing_info *trace_info = alloc_process_trace_info(pid);

	if (!trace_info) {
		pr_err("Failed to allocate process trace_info for PID %d\n", pid);
		return;
	}

	// Lock the list and disable interrupts for thread safety
	raw_spin_lock_irqsave(&proc_list_lock, flags);

	// Add the new trace info to the list
	list_add(&trace_info->list, &process_tracing_list);

	// Unlock the list and restore interrupts
	raw_spin_unlock_irqrestore(&proc_list_lock, flags);
}

/**
 * compare() - Checks if a list entry matches a given key
 * @entry: Pointer to the list entry to check.
 * @key: Key value to compare against the entry.
 * @type: Type of node to determine the comparison method.
 *
 * This function determines if a given list entry matches a specified key,
 * based on the node type. For process nodes, it compares process IDs,
 * and for memory map nodes, it compares memory allocation addresses.
 * Returns true if they match, false otherwise.
 */
bool compare(void *entry, void *key, NodeType type)
{
	switch (type) {
	case PROCESS_NODE: {
		// Extract the process tracing info from the list entry
		struct process_tracing_info *trace_info = list_entry(entry, struct process_tracing_info, list);
		// Cast the key to pid_t pointer and compare it with the pid stored in the trace info
		pid_t *pid = (pid_t *)key;

		return trace_info->pid == *pid;
	}
	case MEMORY_MAP_NODE: {
		// Extract the memory allocation record from the list entry
		struct memory_allocation_record *trace_info = list_entry(entry, struct memory_allocation_record, list);
		// Cast the key and compare it with the allocation address stored in the trace info
		void **address = (void **)key;

		return trace_info->allocation_address == *address;
	}
	default:
		return false;
	}
}

/**
 * remove_elem_from_process_tracing_list() - Removes a process tracing entry from the list
 * @pid: Process ID of the entry to remove.
 *
 * This function iterates over a list of process tracing records and removes the entry
 * corresponding to the specified PID. It ensures safe modification of the list during
 * iteration and frees the memory allocated for the removed entry.
 */
static void remove_elem_from_process_tracing_list(pid_t pid)
{
	struct list_head *runner, *tmp;

	// Iterate over the process list safely against removal within the loop
	list_for_each_safe(runner, tmp, &process_tracing_list) {
		// Use compare function to find the correct process node
		if (compare(runner, &pid, PROCESS_NODE)) {
			struct process_tracing_info *trace_info = list_entry(runner, struct process_tracing_info, list);

			list_del(runner);
			kfree(trace_info);
			break;
		}
	}
}

/**
 * print_tracing_headers() - Prints column headers for tracing data
 * @seq_output: The sequence file to print to.
 *
 * This function formats and prints the column headers for displaying
 * tracer data in a sequence file, ensuring each column is tab-separated.
 */
static void print_tracing_headers(struct seq_file *seq_output)
{
	// Use sequence file print to format the output
	seq_printf(seq_output, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				HEADER_PID, HEADER_KMALLOC, HEADER_KFREE, HEADER_KMALLOC_MEM, HEADER_KFREE_MEM,
				HEADER_SCHED, HEADER_UP, HEADER_DOWN, HEADER_LOCK, HEADER_UNLOCK);
}

/**
 * print_int_data() - Prints an integer to the sequence file
 * @seq_output: The sequence file to print to.
 * @data: Integer data to print.
 *
 * Prints a single integer value followed by a tab to the sequence file,
 * which helps in formatting the tracer output.
 */
static void print_int_data(struct seq_file *seq_output, int data)
{
	seq_printf(seq_output, "%d\t", data);
}

/**
 * print_size_data() - Prints size data to the sequence file
 * @seq_output: The sequence file to print to.
 * @data: Size data to print.
 *
 * This function prints size type data followed by a tab, aiding in the
 * formatted output of tracer data in a sequence file.
 */
static void print_size_data(struct seq_file *seq_output, size_t data)
{
	seq_printf(seq_output, "%zu\t", data);
}

/**
 * print_process_trace_info_data() - Prints detailed tracing information for a process
 * @seq_output: The sequence file to print to.
 * @trace_info: Tracing information structure containing data to print.
 *
 * Outputs all relevant tracing data for a single process into the sequence file,
 * including PID, function call counts, and memory usage, formatted with tabs.
 */
static void print_process_trace_info_data(struct seq_file *seq_output, struct process_tracing_info *trace_info)
{
	// Print each item of the process trace info struct
	print_int_data(seq_output, trace_info->pid);
	print_int_data(seq_output, trace_info->function_call_count[KMALLOC_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[KFREE_KEY]);
	print_size_data(seq_output, trace_info->memory_usage[KMALLOC_KEY]);
	print_size_data(seq_output, trace_info->memory_usage[KFREE_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[SCHED_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[UP_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[DOWN_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[LOCK_KEY]);
	print_int_data(seq_output, trace_info->function_call_count[UNLOCK_KEY]);
	seq_putc(seq_output, '\n');
}

/**
 * proc_file_open() - Opens the proc file and prepares it for reading
 * @inode: Inode structure for the proc file.
 * @file: File structure for the proc file.
 *
 * This function utilizes the single_open utility to facilitate opening
 * the proc file. It links the file with the tracer_print function to handle
 * data output when the file is read.
 *
 * Return: Status of the file open operation.
 */
static int proc_file_open(struct inode *inode, struct file *file)
{
	// Use the single_open utility to handle the open operation
	return single_open(file, tracer_print, NULL);
}

/**
 * tracer_print() - Prints all tracing data to the sequence file
 * @seq_output: The sequence file to print to.
 * @data: Additional data
 *
 * When the proc file is read, this function prints the tracing data headers
 * followed by detailed process tracing information for each entry in the global
 * list. It uses formatted print functions to ensure data readability.
 *
 * Return: Always returns 0 indicating successful execution.
 */
static int tracer_print(struct seq_file *seq_output, void *data)
{
	struct list_head *runner;
	struct process_tracing_info *trace_info;

	// Print headers first
	print_tracing_headers(seq_output);

	// Iterate over all process tracing information and print their data
	list_for_each(runner, &process_tracing_list) {
		trace_info = list_entry(runner, struct process_tracing_info, list);
		print_process_trace_info_data(seq_output, trace_info);
	}

	return 0;
}

/**
 * handle_ioctl_commands() - Handles IOCTL commands for process tracing management
 * @file: The file structure associated with the IOCTL command.
 * @ioctl_cmd: The command identifier indicating the specific action to take.
 * @ioctl_arg: Argument for the IOCTL command.
 *
 * This function interprets and processes IOCTL commands to either add or remove
 * process entries from the tracing list based on the provided PID. It ensures
 * correct command execution and logs warnings for unknown commands.
 *
 * Return: 0 on success, -EINVAL for unknown commands.
 */
static long handle_ioctl_commands(struct file *file, unsigned int ioctl_cmd, unsigned long ioctl_arg)
{
	// Check which command has been sent
	if (ioctl_cmd == TRACER_ADD_PROCESS) {
		// Add a process to the tracing list using the PID provided in ioctl_arg
		add_elem_to_process_tracing_list((pid_t) ioctl_arg);
	} else if (ioctl_cmd == TRACER_REMOVE_PROCESS) {
		// Remove a process from the tracing list using the PID provided
		remove_elem_from_process_tracing_list((pid_t) ioctl_arg);
	} else {
		pr_warn("Unknown IOCTL ioctl_cmd: %u\n", ioctl_cmd);
		return -EINVAL;
	}

	return 0;
}

/**
 * record_tracer_event() - Records a specific event in the process tracing list
 * @pid: Process ID associated with the event.
 * @function_key: Index indicating the function involved in the event.
 * @size: Size involved in the event.
 * @event_type: Type of event, either a call or a memory allocation.
 *
 * This function updates the tracing information for a process in the global list.
 * It increments the call count or updates memory usage based on the event type.
 * This helps in keeping track of function calls and memory usage dynamically.
 */
static void record_tracer_event(pid_t pid, int function_key, size_t size, EventType event_type)
{
	struct list_head *runner;
	struct process_tracing_info *trace_info;

	// Iterate through the process tracing list to find the relevant process
	list_for_each(runner, &process_tracing_list) {
		if (compare(runner, &pid, PROCESS_NODE)) {
			trace_info = list_entry(runner, struct process_tracing_info, list);
			// Increment call count or memory usage based on the event type
			if (event_type == RECORD_CALL)
				trace_info->function_call_count[function_key] += 1;
			else if (event_type == RECORD_MEMORY_ALLOCATION)
				trace_info->memory_usage[function_key] += size;
		}
	}
}

/**
 * handle_kmalloc_entry() - Kretprobe handler for the entry of kmalloc
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * This function is triggered when kmalloc is called in the kernel. It captures
 * the size of the memory allocation request directly from the CPU registers and
 * records this event. It verifies the probe data integrity and returns an error
 * if validation fails.
 *
 * Return: 0 on successful handling, or an error code on failure.
 */
static int handle_kmalloc_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	size_t allocated_size;
	struct kmalloc_probe_data *data;

	// Validate pointers to kprobe_instance and cpu_regs
	if (!kprobe_instance || !cpu_regs)
		return -EINVAL;

	data = (struct kmalloc_probe_data *)kprobe_instance->data;
	// Check if the data pointer was correctly initialized
	if (!data)
		return -EFAULT;

	// Capture the allocated size from the CPU registers
	allocated_size = (size_t)cpu_regs->ax;
	data->allocation_size = allocated_size;

	// Record the kmalloc call and allocation size
	record_tracer_event(current->pid, KMALLOC_KEY, 0, RECORD_CALL);
	record_tracer_event(current->pid, KMALLOC_KEY, allocated_size, RECORD_MEMORY_ALLOCATION);

	return 0;
}

/**
 * handle_kmalloc_return() - Kretprobe handler for the return of kmalloc
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * This function handles the return from a kmalloc call. It retrieves the
 * memory allocation address returned by kmalloc, and logs the allocation by
 * adding it to the memory map list. It handles errors for invalid pointers and
 * unsuccessful additions to the memory map list.
 *
 * Return: 0 on success, or an error code indicating the nature of the failure.
 */
static int handle_kmalloc_return(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	struct kmalloc_probe_data *data;
	void *allocation_address;
	int err;

	// Validate pointers to kprobe_instance and cpu_regs
	if (!kprobe_instance || !cpu_regs) {
		pr_warn("Invalid kretprobe instance or register data\n");
		return -EINVAL;
	}

	// Get the return value of kmalloc, which is the allocation address
	allocation_address = (void *)regs_return_value(cpu_regs);
	if (!allocation_address) {
		pr_err("kmalloc returned NULL\n");
		return -ENOMEM;
	}

	data = (struct kmalloc_probe_data *)kprobe_instance->data;
	// Check if the data was initialized properly
	if (!data) {
		pr_warn("No probe data available\n");
		return -EFAULT;
	}

	// Attempt to add the allocation to the memory map list
	err = add_elem_to_memory_map(allocation_address, data->allocation_size);
	if (err) {
		pr_err("Failed to add memory map element\n");
		return err;
	}

	return 0;
}

/**
 * remove_memory_trace_info() - Removes and deallocates a memory trace entry
 * @runner: Pointer to the list node.
 * @trace_info: Pointer to the memory allocation record to be removed.
 *
 * This function removes a memory allocation record from the tracing list,
 * records the deallocation event, and frees the memory used by the record.
 */
static void remove_memory_trace_info(struct list_head *runner, struct memory_allocation_record *trace_info)
{
	// Record the memory deallocation event
	record_tracer_event(current->pid, KFREE_KEY, trace_info->allocation_size, RECORD_MEMORY_ALLOCATION);
	// Remove the entry from the linked list
	list_del(runner);
	// Free the memory used by the trace info
	kfree(trace_info);
}

/**
 * remove_elem_from_memory_map() - Removes a memory allocation record by address
 * @kfree_address: Address of the memory allocation to remove.
 *
 * This function searches the memory allocation list for a record matching the
 * provided address. If found, it removes the record from the list and updates
 * the tracing data to reflect this change.
 *
 * Return: 0 on successful removal, -ENOENT if no matching record is found.
 */
static int remove_elem_from_memory_map(void *kfree_address)
{
	struct list_head *runner, *tmp;
	struct memory_allocation_record *trace_info;

	// Traverse the list of memory allocations
	list_for_each_safe(runner, tmp, &memory_allocation_list) {
		trace_info = list_entry(runner, struct memory_allocation_record, list);
		// Check if the current list element matches the given address
		if (compare(runner, &kfree_address, MEMORY_MAP_NODE)) {
			// Remove the memory trace information
			remove_memory_trace_info(runner, trace_info);
			return 0;
		}
	}
	return -ENOENT;
}

/**
 * handle_kfree_entry() - Kretprobe handler for the kfree function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Activated when the kfree function is entered in the kernel. It captures the
 * address of the memory being freed from the CPU registers, records the event,
 * and initiates the removal of the corresponding memory allocation record from
 * the global list. It ensures accurate tracking of free operations in the memory tracing.
 *
 * Return: 0 on successful handling, -EINVAL if CPU registers are invalid.
 */
static int handle_kfree_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	void *kfree_address;

	// Validate the CPU registers
	if (!cpu_regs)
		return -EINVAL;

	// Get the address from the register
	kfree_address = (void *) cpu_regs->ax;
	// Record the kfree call event
	record_tracer_event(current->pid, KFREE_KEY, 0, RECORD_CALL);

	// Remove the corresponding memory allocation record
	if (kfree_address)
		remove_elem_from_memory_map(kfree_address);

	return 0;
}

/**
 * handle_schedule_entry() - Kretprobe handler for the schedule function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Records a scheduling event when the kernel's schedule function is entered.
 * This helps track and log the frequency of scheduling operations performed by the kernel.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_schedule_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	record_tracer_event(current->pid, SCHED_KEY, 0, RECORD_CALL);
	return 0;
}

/**
 * handle_up_entry() - Kretprobe handler for semaphore up function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Captures and records an 'up' semaphore event.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_up_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	record_tracer_event(current->pid, UP_KEY, 0, RECORD_CALL);
	return 0;
}

/**
 * handle_down_entry() - Kretprobe handler for semaphore down function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Records a semaphore 'down' event.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_down_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	record_tracer_event(current->pid, DOWN_KEY, 0, RECORD_CALL);
	return 0;
}

/**
 * handle_mutex_lock_entry() - Kretprobe handler for mutex lock function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Logs a mutex lock event.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_mutex_lock_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	record_tracer_event(current->pid, LOCK_KEY, 0, RECORD_CALL);
	return 0;
}

/**
 * handle_mutex_unlock_entry() - Kretprobe handler for mutex unlock function entry
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * Records a mutex unlock event.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_mutex_unlock_entry(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	record_tracer_event(current->pid, UNLOCK_KEY, 0, RECORD_CALL);
	return 0;
}

/**
 * handle_process_exit() - Kretprobe handler for the process exit function
 * @kprobe_instance: Instance of the kretprobe.
 * @cpu_regs: CPU register data available at the probe point.
 *
 * This function handles the cleanup of process tracing information upon process exit.
 *
 * Return: 0 to indicate successful handling.
 */
static int handle_process_exit(struct kretprobe_instance *kprobe_instance, struct pt_regs *cpu_regs)
{
	remove_elem_from_process_tracing_list((pid_t)current->pid);
	return 0;
}

/**
 * register_probe() - Registers a kretprobe with a specified kernel function
 * @probe: The kretprobe instance to be registered.
 * @func_name: Name of the kernel function to attach the probe to.
 *
 * Sets up and registers a kernel return probe for the specified function.
 *
 * Return: 0 on successful registration, negative error code on failure.
 */
static int register_probe(struct kretprobe *probe, const char *func_name)
{
	int error;
	// Assign the function to be probed
	probe->kp.symbol_name = func_name;
	// Register the probe
	error = register_kretprobe(probe);
	if (error < 0)
		return BASE_ERROR_CODE;
	return 0;
}


/**
 * tracer_init() - Initializes the tracer module
 *
 * This function sets up the tracer by registering a miscellaneous device for
 * user-space interactions, creating a proc entry for accessing tracer data, and
 * registering kretprobes for kernel functions that need to be traced.
 * It handles errors in each step and cleans up appropriately if any part fails.
 *
 * Return: 0 on success, or a negative error code if an error occurs during setup.
 */
static int tracer_init(void)
{
	int error;

	// Register a miscellaneous device for user-space interaction
	error = misc_register(&tracer_misc_device);

	if (error) {
		pr_err("Failed to register misc device: %d\n", error);
		return error;
	}

	// Create a proc entry for accessing the tracer's information
	proc_tracing_info_entry = proc_create(PROCFS_TRACER_READ, 0000, NULL, &tracer_proc_ops);
	if (!proc_tracing_info_entry) {
		pr_err("Failed to create proc entry\n");
		// Clean up device registration
		misc_deregister(&tracer_misc_device);
		return -ENOMEM;
	}

	// Register kernel probes for functions to trace
	if ((error = register_probe(&kmalloc_probe, KMALLOC_FUNC_NAME)) < 0 ||
		(error = register_probe(&kfree_probe, KFREE_FUNC_NAME)) < 0 ||
		(error = register_probe(&schedule_probe, SCHED_FUNC_NAME)) < 0 ||
		(error = register_probe(&up_probe, UP_FUNC_NAME)) < 0 ||
		(error = register_probe(&down_probe, DOWN_FUNC_NAME)) < 0 ||
		(error = register_probe(&mutex_lock_probe, LOCK_FUNC_NAME)) < 0 ||
		(error = register_probe(&mutex_unlock_probe, UNLOCK_FUNC_NAME)) < 0 ||
		(error = register_probe(&process_exit_probe, EXIT_FUNC_NAME)) < 0) {
		return error;
	}

	return 0;
}

/**
 * tracer_exit() - Cleans up the tracer module
 *
 * This function is responsible for the cleanup process of the tracer module.
 * It deregisters the miscellaneous device, removes the proc entry, and
 * unregisters all registered kretprobes.
 */
static void tracer_exit(void)
{
	int i;

	// Deregister the miscellaneous device
	misc_deregister(&tracer_misc_device);
	// Remove the proc entry
	proc_remove(proc_tracing_info_entry);

	// Loop over and unregister all registered kernel return probes
	for (i = 0; i < NUM_KRETPROBES; i++) {
		if (all_kretprobes[i]) {
			unregister_kretprobe(all_kretprobes[i]);
			// Nullify the handler to prevent any dangling pointer issues
			all_kretprobes[i]->handler = NULL;
		}
	}
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Adina-Maria Amzarescu");
MODULE_LICENSE("GPL v2");
