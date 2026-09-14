#include "common/hostException.h"

#include <atomic>
#include <cstdio>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <algorithm>
#include <windows.h> // IWYU pragma: keep
#else
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <initializer_list>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h> // IWYU pragma: keep
#endif
#endif

// IWYU pragma: no_include <errhandlingapi.h>
// IWYU pragma: no_include <excpt.h>
// IWYU pragma: no_include <minwinbase.h>
// IWYU pragma: no_include <minwindef.h>
// IWYU pragma: no_include <wtypes.h>

namespace Common::HostException {

#if !defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);
#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX

// macOS uses the same POSIX platform setting and needs a signal stack too.
class ThreadSignalStack {
public:
	ThreadSignalStack() {
		const auto page_size = static_cast<size_t>(::getpagesize());
		const auto stack_size =
		    (std::max<size_t>(64 * 1024, MINSIGSTKSZ) + page_size - 1) & ~(page_size - 1);
		if (::posix_memalign(&m_memory, page_size, stack_size) != 0) {
			return;
		}

		stack_t stack {};
		stack.ss_sp   = m_memory;
		stack.ss_size = stack_size;
		if (::sigaltstack(&stack, &m_previous) != 0) {
			std::free(m_memory);
			m_memory = nullptr;
		}
	}

	~ThreadSignalStack() {
		if (m_memory != nullptr && ::sigaltstack(&m_previous, nullptr) == 0) {
			std::free(m_memory);
		}
	}

	[[nodiscard]] bool IsInitialized() const { return m_memory != nullptr; }

	KYTY_CLASS_NO_COPY(ThreadSignalStack)

private:
	void*   m_memory = nullptr;
	stack_t m_previous {};
};

bool InitializeThreadSignalStack() {
	// Keep fault handling off guest stacks, which GPU tracking can make read-only.
	thread_local ThreadSignalStack signal_stack;
	return signal_stack.IsInitialized();
}

#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS

static bool IsReadableWindowsRange(uint64_t addr, uint64_t size) noexcept {
	if (addr == 0 || size == 0 || addr + size < addr) {
		return false;
	}
	const uint64_t end = addr + size;
	for (uint64_t current = addr; current < end;) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQuery(reinterpret_cast<const void*>(current), &mbi, sizeof(mbi)) == 0 ||
		    mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
			return false;
		}
		const auto region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
		if (region_end <= current) {
			return false;
		}
		current = std::min(region_end, end);
	}
	return true;
}

static void DumpLowAddressGuestFault(const ExceptionInfo& info) noexcept {
	constexpr uint64_t MAIN_GUEST_BASE = 0x0000000900000000ull;
	constexpr uint64_t GUEST_CODE_END  = 0x0000001000000000ull;

	if (info.type != ExceptionType::AccessViolation || info.access_violation_vaddr >= 0x1000 ||
	    info.exception_address < MAIN_GUEST_BASE || info.exception_address >= GUEST_CODE_END) {
		return;
	}

	std::printf("--- Extended low-address guest fault diagnostics ---\n");
	std::printf("guest_pc=0x%016llx main_image_offset=0x%llx fault_addr=0x%016llx\n",
	            static_cast<unsigned long long>(info.exception_address),
	            static_cast<unsigned long long>(info.exception_address - MAIN_GUEST_BASE),
	            static_cast<unsigned long long>(info.access_violation_vaddr));

	constexpr uint64_t code_before = 256;
	constexpr uint64_t code_after  = 64;
	if (info.exception_address >= code_before &&
	    IsReadableWindowsRange(info.exception_address - code_before, code_before + code_after)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info.exception_address - code_before);
		std::printf("extended_code (pc-256 .. pc+64, fault at byte 256):");
		for (uint64_t i = 0; i < code_before + code_after; ++i) {
			std::printf("%s%02x", (i % 16 == 0) ? "\n " : " ", code[i]);
		}
		std::printf("\n");
	}

	constexpr uint64_t stack_before = 128;
	constexpr uint64_t stack_after  = 640;
	if (info.rsp >= stack_before &&
	    IsReadableWindowsRange(info.rsp - stack_before, stack_before + stack_after)) {
		const auto stack_start = info.rsp - stack_before;
		const auto* stack       = reinterpret_cast<const uint64_t*>(stack_start);
		constexpr uint64_t qwords = (stack_before + stack_after) / sizeof(uint64_t);
		std::printf("extended_stack (rsp-128 .. rsp+640; rsp is qword 16):");
		for (uint64_t i = 0; i < qwords; ++i) {
			std::printf("%s %016llx", (i % 4 == 0) ? "\n " : "",
			            static_cast<unsigned long long>(stack[i]));
		}
		std::printf("\n");

		std::printf("guest-code-looking stack values:");
		for (uint64_t i = 0; i < qwords; ++i) {
			const uint64_t value = stack[i];
			if (value >= MAIN_GUEST_BASE && value < GUEST_CODE_END) {
				const int64_t rel_qword = static_cast<int64_t>(i) - 16;
				std::printf("\n [%+lld qwords] 0x%016llx main+0x%llx", static_cast<long long>(rel_qword),
				            static_cast<unsigned long long>(value),
				            static_cast<unsigned long long>(value - MAIN_GUEST_BASE));
			}
		}
		std::printf("\n");
	}

	struct NamedReg {
		const char* name;
		uint64_t    value;
	};
	const NamedReg regs[] = {{"rax", info.rax}, {"rbx", info.rbx}, {"rcx", info.rcx},
	                         {"rdx", info.rdx}, {"rsi", info.rsi}, {"rdi", info.rdi},
	                         {"rbp", info.rbp}, {"r8", info.r8},   {"r9", info.r9},
	                         {"r10", info.r10}, {"r11", info.r11}, {"r12", info.r12},
	                         {"r13", info.r13}, {"r14", info.r14}, {"r15", info.r15}};
	for (const auto& reg: regs) {
		if (reg.value < 0x10000 || !IsReadableWindowsRange(reg.value, 16 * sizeof(uint64_t))) {
			continue;
		}
		const auto* words = reinterpret_cast<const uint64_t*>(reg.value);
		std::printf("mem[%s=0x%016llx]:", reg.name, static_cast<unsigned long long>(reg.value));
		for (int i = 0; i < 16; ++i) {
			std::printf("%s %016llx", (i % 4 == 0) ? "\n " : "",
			            static_cast<unsigned long long>(words[i]));
		}
		std::printf("\n");
	}
	std::fflush(stdout);
}

static LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS exception) noexcept {
	auto* exception_record = exception->ExceptionRecord;

	if (exception_record->ExceptionCode == DBG_PRINTEXCEPTION_C ||
	    exception_record->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (exception_record->ExceptionCode == 0x406D1388) {
		// Set a thread name.
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	ExceptionInfo info {};
	info.exception_address = reinterpret_cast<uint64_t>(exception_record->ExceptionAddress);
	info.native_code       = exception_record->ExceptionCode;
	info.native_context    = exception->ContextRecord;

	if (exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		info.type = ExceptionType::AccessViolation;
		switch (exception_record->ExceptionInformation[0]) {
			case 0: info.access_violation_type = AccessViolationType::Read; break;
			case 1: info.access_violation_type = AccessViolationType::Write; break;
			case 8: info.access_violation_type = AccessViolationType::Execute; break;
			default: info.access_violation_type = AccessViolationType::Unknown; break;
		}
		info.access_violation_vaddr = exception_record->ExceptionInformation[1];
	} else if (exception_record->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	info.rax = exception->ContextRecord->Rax;
	info.rbx = exception->ContextRecord->Rbx;
	info.rcx = exception->ContextRecord->Rcx;
	info.rdx = exception->ContextRecord->Rdx;
	info.rsi = exception->ContextRecord->Rsi;
	info.rdi = exception->ContextRecord->Rdi;
	info.rbp = exception->ContextRecord->Rbp;
	info.rsp = exception->ContextRecord->Rsp;
	info.r8  = exception->ContextRecord->R8;
	info.r9  = exception->ContextRecord->R9;
	info.r10 = exception->ContextRecord->R10;
	info.r11 = exception->ContextRecord->R11;
	info.r12 = exception->ContextRecord->R12;
	info.r13 = exception->ContextRecord->R13;
	info.r14 = exception->ContextRecord->R14;
	info.r15 = exception->ContextRecord->R15;

	DumpLowAddressGuestFault(info);

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

#elif defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);

// Translate the x86-64 page-fault error code (mcontext __es.__err) into an access type.
// bit 1 (0x2) = write, bit 4 (0x10) = instruction fetch, otherwise a read.
static AccessViolationType DecodeAccess(uint64_t err) {
	if ((err & 0x10u) != 0) {
		return AccessViolationType::Execute;
	}
	if ((err & 0x2u) != 0) {
		return AccessViolationType::Write;
	}
	return AccessViolationType::Read;
}

// POSIX signal handler that mirrors the Windows vectored handler: build an ExceptionInfo
// from the mcontext and dispatch. A resolved fault (handler returns true) simply returns,
// re-executing the faulting instruction against the now-fixed protection. An unresolved
// fault restores the default disposition so the retry terminates the process.
static void SignalHandler(int sig, siginfo_t* si, void* uctx) {
	auto*       uc = static_cast<ucontext_t*>(uctx);
	const auto* mc = uc->uc_mcontext;
	const auto& ss = mc->__ss;

	ExceptionInfo info {};
	info.exception_address = ss.__rip;
	info.native_code       = static_cast<uint32_t>(si->si_code);
	info.native_context    = uctx;

	if (sig == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		info.type                   = ExceptionType::AccessViolation;
		info.access_violation_type  = DecodeAccess(mc->__es.__err);
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(si->si_addr);
	}

	info.rax = ss.__rax;
	info.rbx = ss.__rbx;
	info.rcx = ss.__rcx;
	info.rdx = ss.__rdx;
	info.rsi = ss.__rsi;
	info.rdi = ss.__rdi;
	info.rbp = ss.__rbp;
	info.rsp = ss.__rsp;
	info.r8  = ss.__r8;
	info.r9  = ss.__r9;
	info.r10 = ss.__r10;
	info.r11 = ss.__r11;
	info.r12 = ss.__r12;
	info.r13 = ss.__r13;
	info.r14 = ss.__r14;
	info.r15 = ss.__r15;

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return; // retry the faulting instruction against the fixed mapping
	}

	// Unresolved: restore the default action so the re-executed instruction terminates.
	struct sigaction dfl {};
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(sig, &dfl, nullptr);
}

#else

// x86-64 page-fault error bits.
constexpr uint64_t PAGE_FAULT_ERROR_WRITE       = 0x02;
constexpr uint64_t PAGE_FAULT_ERROR_INSTRUCTION = 0x10;

// Let the kernel handle an unresolved fault on retry.
static void ChainToDefault(int signal_number) noexcept {
	struct sigaction restore {};
	restore.sa_handler = SIG_DFL;
	sigemptyset(&restore.sa_mask);
	restore.sa_flags = 0;
	::sigaction(signal_number, &restore, nullptr);
}

static void SignalHandler(int signal_number, siginfo_t* signal_info, void* native_context) {
	auto* context = static_cast<ucontext_t*>(native_context);
	auto* gregs   = context->uc_mcontext.gregs;

	ExceptionInfo info {};
	info.exception_address = static_cast<uint64_t>(gregs[REG_RIP]);
	info.native_code       = static_cast<uint32_t>(signal_number);
	info.native_context    = context;

	if (signal_number == SIGSEGV || signal_number == SIGBUS) {
		info.type             = ExceptionType::AccessViolation;
		const auto error_code = static_cast<uint64_t>(gregs[REG_ERR]);
		if ((error_code & PAGE_FAULT_ERROR_INSTRUCTION) != 0) {
			info.access_violation_type = AccessViolationType::Execute;
		} else if ((error_code & PAGE_FAULT_ERROR_WRITE) != 0) {
			info.access_violation_type = AccessViolationType::Write;
		} else {
			info.access_violation_type = AccessViolationType::Read;
		}
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(signal_info->si_addr);
	} else if (signal_number == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		ChainToDefault(signal_number);
		return;
	}

	info.rax = static_cast<uint64_t>(gregs[REG_RAX]);
	info.rbx = static_cast<uint64_t>(gregs[REG_RBX]);
	info.rcx = static_cast<uint64_t>(gregs[REG_RCX]);
	info.rdx = static_cast<uint64_t>(gregs[REG_RDX]);
	info.rsi = static_cast<uint64_t>(gregs[REG_RSI]);
	info.rdi = static_cast<uint64_t>(gregs[REG_RDI]);
	info.rbp = static_cast<uint64_t>(gregs[REG_RBP]);
	info.rsp = static_cast<uint64_t>(gregs[REG_RSP]);
	info.r8  = static_cast<uint64_t>(gregs[REG_R8]);
	info.r9  = static_cast<uint64_t>(gregs[REG_R9]);
	info.r10 = static_cast<uint64_t>(gregs[REG_R10]);
	info.r11 = static_cast<uint64_t>(gregs[REG_R11]);
	info.r12 = static_cast<uint64_t>(gregs[REG_R12]);
	info.r13 = static_cast<uint64_t>(gregs[REG_R13]);
	info.r14 = static_cast<uint64_t>(gregs[REG_R14]);
	info.r15 = static_cast<uint64_t>(gregs[REG_R15]);

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return;
	}

	ChainToDefault(signal_number);
}

#endif

bool InstallHandler(Handler handler) {
	if (handler == nullptr) {
		return false;
	}

	uint32_t expected_state = 0;
	if (!g_install_state.compare_exchange_strong(expected_state, 1, std::memory_order_acq_rel)) {
		return expected_state == 2 && g_handler.load(std::memory_order_acquire) == handler;
	}

	g_handler.store(handler, std::memory_order_release);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (AddVectoredExceptionHandler(0, ExceptionFilter) == nullptr) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("AddVectoredExceptionHandler() failed\n");
		return false;
	}
#elif defined(__APPLE__)
	struct sigaction sa {};
	sa.sa_sigaction = SignalHandler;
	sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	// The guest signal-dispatch path (KernelRaiseException) interrupts threads with
	// SIGUSR1; block it while a fault is being resolved so a stop-the-world request
	// cannot preempt the handler between the protection fix and the retry.
	sigaddset(&sa.sa_mask, SIGUSR1);

	// macOS raises SIGBUS for protection faults on some paths and SIGSEGV on others;
	// SIGILL covers instructions the host cannot execute (routed to the x64 emulator).
	bool ok = sigaction(SIGSEGV, &sa, nullptr) == 0 && sigaction(SIGBUS, &sa, nullptr) == 0 &&
	          sigaction(SIGILL, &sa, nullptr) == 0;
	if (!ok) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("sigaction() failed to install the host fault handler\n");
		return false;
	}
#else
	struct sigaction action {};
	action.sa_sigaction = SignalHandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

	for (const int signal_number: {SIGSEGV, SIGBUS, SIGILL}) {
		if (::sigaction(signal_number, &action, nullptr) != 0) {
			g_handler.store(nullptr, std::memory_order_release);
			g_install_state.store(0, std::memory_order_release);
			printf("sigaction(%d) failed\n", signal_number);
			return false;
		}
	}
#endif

	g_install_state.store(2, std::memory_order_release);
	return true;
}

} // namespace Common::HostException
