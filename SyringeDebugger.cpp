#include "SyringeDebugger.h"

#include "CRC32.h"
#include "FindFile.h"
#include "Handle.h"
#include "Log.h"
#include "Support.h"
#include "Setting.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <memory>
#include <numeric>

#include <DbgHelp.h>

using namespace std;

std::string UnicodetoANSI(const std::wstring& Unicode)
{
	int ANSIlen = WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, 0, 0, 0, 0);// 获取UTF-8编码长度
	char* ANSI = new CHAR[ANSIlen + 4]{};
	WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, ANSI, ANSIlen, 0, 0); //转换成UTF-8编码
	std::string ret = ANSI;
	delete[] ANSI;
	return ret;
}

std::pair<DWORD, std::string> SyringeDebugger::AnalyzeAddr(DWORD Addr)
{
	if (Database.InRange(Addr))
	{
		return Database.AnalyzeDBAddr(Addr);
	}
	for (size_t i = 0; i < LibBase.size() - 1; i++)
	{
		if (LibBase[i].BaseAddr <= Addr && Addr < LibBase[i + 1].BaseAddr)
			return std::make_pair(Addr - LibBase[i].BaseAddr, std::move(UnicodetoANSI(LibBase[i].Name)));
	}
	if (LibBase.back().BaseAddr <= Addr)
		return std::make_pair(Addr - LibBase.back().BaseAddr, std::move(UnicodetoANSI(LibBase.back().Name)));
	return std::make_pair(Addr, "UNKNOWN");
}


const std::string& UniqueIDByPath()
{
	static std::string Result{};
	if (!Result.empty())return Result;
	auto id = QuickHashCStrUpper(ExecutableDirectoryPath().c_str());
	Result = std::to_string(id);
	return Result;
}

void RemoteMapper::Create(SharedMemHeader& rcd, int RemoteMapSuffix, const std::string& Prefix)
{
	if (!rcd.TotalSize)return;
	hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, rcd.TotalSize, (Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str());
	//MessageBoxA(NULL,(Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str(), "Syringe Side", MB_OK);
	if (!hMap)return;
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, rcd.TotalSize);
	if (!View)return;
	memcpy(View, &rcd, sizeof(SharedMemHeader));
	Size = rcd.TotalSize;
}
void RemoteMapper::Open(int RemoteMapSuffix, const std::string& Prefix)
{
	hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, (Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str());
	if (!hMap)return;
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemHeader));
	if (!View)return;
	auto pHeader = Header();
	Size = pHeader->TotalSize;
	UnmapViewOfFile(View);
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, Size);
	if (!View)Size = 0;
}
bool RemoteMapper::Available()
{
	return View != nullptr;
}
RemoteMapper::RemoteMapper() :hMap(NULL), View(nullptr), Size(0) {}
RemoteMapper::~RemoteMapper()
{
	if (View)UnmapViewOfFile(View);
	if (hMap)CloseHandle(hMap);
}

//bool SyringeReceive(char const* const lib);

void SyringeDebugger::DebugProcess(std::string_view const arguments)
{
	STARTUPINFO startupInfo{ sizeof(startupInfo) };

	SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

	auto command_line = '"' + exe + "\" ";
	command_line += arguments;

	if(CreateProcess(
		exe.c_str(), command_line.data(), nullptr, nullptr, false,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
		nullptr, nullptr, &startupInfo, &pInfo) == FALSE)
	{
		throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
	}
}

bool SyringeDebugger::PatchMem(void* address, void const* buffer, DWORD size)
{
	return (WriteProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

bool SyringeDebugger::ReadMem(void const* address, void* buffer, DWORD size)
{
	return (ReadProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

VirtualMemoryHandle SyringeDebugger::AllocMem(void* address, size_t size)
{
	if(VirtualMemoryHandle res{ pInfo.hProcess, address, size }) {
		return res;
	}

	throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
}

bool SyringeDebugger::SetBP(void* address)
{
	// save overwritten code and set INT 3
	if(auto& opcode = Breakpoints[address].original_opcode; opcode == 0x00) {
		auto const buffer = INT3;
		ReadMem(address, &opcode, 1);
		return PatchMem(address, &buffer, 1);
	}

	return true;
}

DWORD __fastcall SyringeDebugger::RelativeOffset(void const* pFrom, void const* pTo)
{
	auto const from = reinterpret_cast<DWORD>(pFrom);
	auto const to = reinterpret_cast<DWORD>(pTo);

	return to - from;
}

const char ExLib[300] = "SyringeEx.dll";
const char ExProc[300] = "Initialize";

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	if(exceptCode == EXCEPTION_BREAKPOINT)
		//整个载入流程都在这了。不用管Return，哥们，这里写代码的顺序就是执行的顺序，这个函数会连续执行好几千次，从前到后把每一块执行完毕
	{
		auto& threadInfo = Threads[dbgEvent.dwThreadId];
		HANDLE currentThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(currentThread, &context);

		// entry breakpoint
		if(bEntryBP)
		{
			bEntryBP = false;
			return DBG_CONTINUE;
		}

		// fix single step repetition issues
		if(context.EFlags & 0x100)
		{
			auto const buffer = INT3;
			context.EFlags &= ~0x100;
			PatchMem(threadInfo.lastBP, &buffer, 1);
		}

		// load DLLs and retrieve proc addresses
		if(!bDLLsLoaded)
		{
			
			// restore
			PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);

			if (!LoadedCount && DLLs.size())
			{
				RemoteMapSuffix = pInfo.dwProcessId;
				SharedMemHeader hd;
				hd.WritingComplete = 0;
				hd.RecordCount = DLLs.size();
				hd.RecordSize = sizeof(SharedMemRecord);
				hd.TotalSize = hd.RecordCount * hd.RecordSize + sizeof(SharedMemHeader);
				Mapper.Create(hd, RemoteMapSuffix, "SYRINGE");
				auto pArr = Mapper.OffsetPtr<SharedMemRecord>(sizeof(SharedMemHeader));
				for (size_t i = 0; i < DLLShort.size(); i++)
				{
					pArr[i].TargetHash = QuickHashCStrUpper(DLLShort[i].c_str());
				}

				if (RunningYR)
				{
					Log::WriteLine(__FUNCTION__ ": 正在写入运行前信息……");
					Log::WriteLine(__FUNCTION__ ": 假定启动了标准的YR V1.001。");
					Database.CreateData();
					Log::WriteLine(__FUNCTION__ ": 运行前信息创建完毕。");
					Database.WriteToStream();
					for (auto& p : LibExt)Database.CopyAndPush(p.second.GetMemCopy());
					Database.CopyAndPushEnd();
					Log::WriteLine(__FUNCTION__ ": 运行前信息打包完毕。");
					Database.SendData();
					Log::WriteLine(__FUNCTION__ ": 运行前信息写入完毕。");
				}
			}
			if (LoadedCount < (int)DLLs.size())
			{
				strcpy(ExLoadingLib, DLLs[LoadedCount].c_str());
				PatchMem(&GetData()->LibName, ExLoadingLib, MaxNameLength);
				PatchMem(&GetData()->ProcName, ExProc, MaxNameLength);

				Log::WriteLine(__FUNCTION__ ": 预加载 （%d/%d）%s", LoadedCount + 1, DLLs.size() + 1, DLLShort[LoadedCount].c_str());
				LoadedCount++;
				
				context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
				context.EFlags |= 0x100;
				context.ContextFlags = CONTEXT_CONTROL;
				SetThreadContext(currentThread, &context);
				threadInfo.lastBP = exceptAddr;
				return DBG_CONTINUE;
			}

			if (FirstHook)
			{

				PatchMem(&GetData()->LibName, ExLib, MaxNameLength);
				PatchMem(&GetData()->ProcName, ExProc, MaxNameLength);
				Log::WriteLine(__FUNCTION__ ": 预加载 （%d/%d）SyringeEx.dll", DLLs.size() + 1, DLLs.size() + 1);

				context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
				FirstHook = false;
				context.EFlags |= 0x100;
				context.ContextFlags = CONTEXT_CONTROL;
				SetThreadContext(currentThread, &context);
				threadInfo.lastBP = exceptAddr;
				return DBG_CONTINUE;
			}
#pragma warning(push)
#pragma warning(disable:4244)//屏蔽有关toupper的警告
			if(loop_LoadLibrary == v_AllHooks.end())
			{
				auto pHeader = Mapper.OffsetPtr<SharedMemHeader>(0);
				if (Mapper.Available())
				{
					if(DLLs.size())while (!pHeader->WritingComplete);
					auto pArr = Mapper.OffsetPtr<SharedMemRecord>(sizeof(SharedMemHeader));
					for (size_t i = 0; i < DLLShort.size(); i++)
					{
						Log::WriteLine("通过Syringe载入的DLL: %s = 0x%08X", DLLShort[i].c_str(), pArr[i].BaseAddr);
						std::transform(DLLShort[i].begin(), DLLShort[i].end(), DLLShort[i].begin(), ::toupper);
						//LibAddr[DLLShort[i]] = pArr[i].BaseAddr;
					}

					LibBase.resize(Mapper.Header()->DllRecordCount);
					//Log::WriteLine("All DLL: at 0x%08X", Mapper.Header()->DllRecordAddr);
					if (!ReadMem((LPCVOID)Mapper.Header()->DllRecordAddr, (LPVOID)LibBase.data(), Mapper.Header()->DllRecordCount * sizeof(SharedMemRecord)))
						Log::WriteLine(__FUNCTION__ ": 载入DLL读入失败。");
					std::sort(LibBase.begin(), LibBase.end(), [](const auto& lhs, const auto& rhs)->bool
						{
							return lhs.BaseAddr < rhs.BaseAddr;
						});
					int j = 1;
					for (auto p : LibBase)
					{
						auto Str = UnicodetoANSI(p.Name);
						std::transform(Str.begin(), Str.end(), Str.begin(), ::toupper);
						LibAddr[Str] = p.BaseAddr;
						Log::WriteLine("获取模块（%d/%d）：%hs = 0x%08X", j, LibBase.size(), Str.c_str(), p.BaseAddr);
						++j;
					}

					for (auto& it : BreakpointRel)
					{
						for (auto& i : it.second.hooks)
						{
							for (char* p = i.RelativeLib; *p; ++p)
							{
								*p = ::toupper(*p);
							}
							auto ait = LibAddr.find(i.RelativeLib);
							if (ait == LibAddr.end())
							{
								Log::WriteLine(__FUNCTION__ ": 无法载入相对钩子：来自库\"%s\"的函数\"%s\"试图从未通过Syringe载入的\"%s\"寻址。", i.lib, i.proc, i.RelativeLib);
								continue;
							}
							auto& hks = Breakpoints[(LPVOID)((DWORD)it.first + ait->second)].hooks;
							hks.push_back(i);
							v_AllHooks.push_back(&hks.back());
							//Log::WriteLine("载入相对钩子：来自库\"%s\"的函数\"%s\"，位于%s + 0x%X (0x%08X)。", i.lib, i.proc, i.RelativeLib, it.first, ((DWORD)it.first + ait->second));
						}
					}
				}
				loop_LoadLibrary = v_AllHooks.begin();
#pragma warning(pop)
			}
			else
			{
				auto const& hook = *loop_LoadLibrary;
				ReadMem(&GetData()->ProcAddress, &hook->proc_address, 4);

				if(!hook->proc_address) {
					Log::WriteLine(
						__FUNCTION__ ": 不能在 %s 库中找到函数"
						" %s", hook->lib, hook->proc);
				}

				++loop_LoadLibrary;
			}

			if(loop_LoadLibrary != v_AllHooks.end())
			{
				auto const& hook = *loop_LoadLibrary;
				PatchMem(&GetData()->LibName, hook->lib, MaxNameLength);
				PatchMem(&GetData()->ProcName, hook->proc, MaxNameLength);

				context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
			}
			else
			{
				Log::WriteLine(__FUNCTION__ ": 成功载入所需函数地址.");
				Log::Flush();
				bDLLsLoaded = true;

				context.Eip = reinterpret_cast<DWORD>(pcEntryPoint);
			}

			// single step mode
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		}

		if(exceptAddr == pcEntryPoint)
		{
			if(!bHooksCreated)
			{
				Log::WriteLine(__FUNCTION__ ": 开始启动DLL，并创建钩子。");

				static BYTE const code_call[] =
				{
					0x60, 0x9C, // PUSHAD, PUSHFD
					0x68, INIT, INIT, INIT, INIT, // PUSH HookAddress
					0x54, // PUSH ESP
					0xE8, INIT, INIT, INIT, INIT, // CALL ProcAddress
					0x83, 0xC4, 0x08, // ADD ESP, 8
					0xA3, INIT, INIT, INIT, INIT, // MOV ds:ReturnEIP, EAX
					0x9D, 0x61, // POPFD, POPAD
					0x83, 0x3D, INIT, INIT, INIT, INIT, 0x00, // CMP ds:ReturnEIP, 0
					0x74, 0x06, // JZ .proceed
					0xFF, 0x25, INIT, INIT, INIT, INIT, // JMP ds:ReturnEIP
				};

				static BYTE const jmp_back[] = { 0xE9, INIT, INIT, INIT, INIT };
				static BYTE const jmp[] = { 0xE9, INIT, INIT, INIT, INIT };

				std::vector<BYTE> code;

				for(auto& it : Breakpoints)
				{
					//Log::WriteLine("将在 0x%08X 处插入钩子。", it.first);
					if(it.first == nullptr || it.first == pcEntryPoint)
					{
						continue;
					}

					auto const [count, overridden] = std::accumulate(
						it.second.hooks.cbegin(), it.second.hooks.cend(),
						std::make_pair(0u, 0u), [](auto acc, auto const& hook)
					{
						if(hook.proc_address) {
							if(acc.second < hook.num_overridden) {
								acc.second = hook.num_overridden;
							}
							acc.first++;
						}
						return acc;
					});

					if(!count)
					{
						continue;
					}

					auto const sz = count * sizeof(code_call)
						+ sizeof(jmp_back) + overridden;

					code.resize(sz);
					auto p_code = code.data();

					it.second.p_caller_code = AllocMem(nullptr, sz);
					auto const base = it.second.p_caller_code.get();

					// write caller code
					for(auto const& hook : it.second.hooks)
					{
						if(hook.proc_address)
						{
							ApplyPatch(p_code, code_call); // code
							ApplyPatch(p_code + 0x03, it.first); // PUSH HookAddress

							auto const rel = RelativeOffset(
								base + (p_code - code.data() + 0x0D), hook.proc_address);
							ApplyPatch(p_code + 0x09, rel); // CALL

							auto const pdReturnEIP = &GetData()->ReturnEIP;
							ApplyPatch(p_code + 0x11, pdReturnEIP); // MOV
							ApplyPatch(p_code + 0x19, pdReturnEIP); // CMP
							ApplyPatch(p_code + 0x22, pdReturnEIP); // JMP ds:ReturnEIP

							p_code += sizeof(code_call);
						}
					}

					// write overridden bytes
					if(overridden)
					{
						ReadMem(it.first, p_code, overridden);
						p_code += overridden;
					}

					// write the jump back
					auto const rel = RelativeOffset(
						base + (p_code - code.data() + 0x05),
						static_cast<BYTE*>(it.first) + 0x05);
					ApplyPatch(p_code, jmp_back);
					ApplyPatch(p_code + 0x01, rel);

					PatchMem(base, code.data(), code.size());

					// dump
					/*
					Log::WriteLine("Call dump for 0x%08X at 0x%08X:", it.first, base);

					code.resize(sz);
					ReadMem(it.second.p_caller_code, code.data(), sz);

					std::string dump_str{ "\t\t" };
					for(auto const& byte : code) {
						char buffer[0x10];
						sprintf(buffer, "%02X ", byte);
						dump_str += buffer;
					}

					Log::WriteLine(dump_str.c_str());
					Log::WriteLine();*/

					// patch original code
					auto const p_original_code = static_cast<BYTE*>(it.first);

					auto const rel2 = RelativeOffset(p_original_code + 5, base);
					code.assign(std::max(overridden, sizeof(jmp)), NOP);
					ApplyPatch(code.data(), jmp);
					ApplyPatch(code.data() + 0x01, rel2);

					DWORD OldProtect;
					VirtualProtectEx(pInfo.hProcess, p_original_code, code.size(), PAGE_EXECUTE_READWRITE, &OldProtect);
					if (PatchMem(p_original_code, code.data(), code.size()))
					{
						//Log::WriteLine("在 0x%08X 处插入钩子入口。", p_original_code);
					}
					else
					{
						Log::WriteLine("无法在 0x%08X 处插入钩子入口。", p_original_code);
					}
					VirtualProtectEx(pInfo.hProcess, p_original_code, code.size(), OldProtect, &OldProtect);
				}
				Log::Flush();
				bHooksCreated = true;
			}

			// restore
			PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);

			// single step mode
			context.EFlags |= 0x100;
			--context.Eip;

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		} 
		else
		{
			// could be a Debugger class breakpoint to call a patching function!

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			return DBG_EXCEPTION_NOT_HANDLED;
		}
	}
	else if(exceptCode == EXCEPTION_SINGLE_STEP)
	{
		auto const buffer = INT3;
		auto const& threadInfo = Threads[dbgEvent.dwThreadId];
		PatchMem(threadInfo.lastBP, &buffer, 1);

		HANDLE hThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);

		context.EFlags &= ~0x100;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(hThread, &context);

		return DBG_CONTINUE;
	}
	else
	{
		auto [Rel, Str] = AnalyzeAddr((DWORD)exceptAddr);
		Log::WriteLine(
			__FUNCTION__ ": 发生异常，代码: 0x%08X 地址： 0x%08X（%s+%X）", exceptCode,
			exceptAddr, Str.c_str(), Rel);

		if(!bAVLogged)
		{
			//Log::WriteLine(__FUNCTION__ ": ACCESS VIOLATION at 0x%08X!", exceptAddr);
			auto const& threadInfo = Threads[dbgEvent.dwThreadId];
			HANDLE currentThread = threadInfo.Thread;

			char const* access = nullptr;
			switch(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
			{
			case 0: access = "读取"; break;
			case 1: access = "写入"; break;
			case 8: access = "执行"; break;
			}

			auto [Rel2, Str2] = AnalyzeAddr((DWORD)dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);
			Log::WriteLine("\t程序试图%s 0x%08X（%s+%X）。",
				access ? access: std::to_string(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0]).c_str(),
				dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1], Str2.c_str(), Rel2);

			CONTEXT context;
			context.ContextFlags = CONTEXT_FULL;
			GetThreadContext(currentThread, &context);

			Log::WriteLine();
			Log::WriteLine("寄存器：");
			Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
				context.Eax, context.Ecx, context.Edx);
			Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
				context.Ebx, context.Esp, context.Ebp);
			Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
				context.Esi, context.Edi, context.Eip);
			Log::WriteLine();

			Log::WriteLine("\t堆栈转储信息：");
			auto const esp = reinterpret_cast<DWORD*>(context.Esp);
			for(auto p = esp; p < &esp[0x100]; ++p) {
				DWORD dw;
				if(ReadMem(p, &dw, 4)) {
					Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
				} else {
					Log::WriteLine("\t0x%08X:\t（无法读取）", p);
				}
			}
			Log::WriteLine();

#if 0
			Log::WriteLine("Making crash dump:\n");
			MINIDUMP_EXCEPTION_INFORMATION expParam;
			expParam.ThreadId = dbgEvent.dwThreadId;
			EXCEPTION_POINTERS ep;
			ep.ExceptionRecord = const_cast<PEXCEPTION_RECORD>(&dbgEvent.u.Exception.ExceptionRecord);
			ep.ContextRecord = &context;
			expParam.ExceptionPointers = &ep;
			expParam.ClientPointers = FALSE;

			wchar_t filename[MAX_PATH];
			wchar_t path[MAX_PATH];
			SYSTEMTIME time;

			GetLocalTime(&time);
			GetCurrentDirectoryW(MAX_PATH, path);

			swprintf(filename, MAX_PATH, L"%s\\syringe.crashed.%04u%02u%02u-%02u%02u%02u.dmp",
				path, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

			HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);

			MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

			MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, nullptr, nullptr);
			CloseHandle(dumpFile);

			Log::WriteLine("Crash dump generated.\n");
#endif

			bAVLogged = true;
		}

		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}



void SyringeDebugger::Run(std::string_view const arguments)
{
	constexpr auto AllocDataSize = sizeof(AllocData);

	Log::WriteLine(
		__FUNCTION__ ": 开始调试。 命令行： \"%s %.*s\"",
		exe.c_str(), printable(arguments));
	DebugProcess(arguments);

	Log::WriteLine(__FUNCTION__ ": 分配了 0x%u 个字节的内存。", AllocDataSize);
	pAlloc = AllocMem(nullptr, AllocDataSize);

	

	Log::WriteLine(__FUNCTION__ ": 该段内存的地址： 0x%08X", pAlloc.get());

	// write DLL loader code
	Log::WriteLine(__FUNCTION__ ": 正在写入DLL的载入、调用代码……");

	static BYTE const cLoadLibrary[] = {
		//0x50, // push eax
		//0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, //mov eax, fs:[0x30]
		//0xA3, INIT, INIT, INIT, INIT, //mov PEBTableEntry, eax
		//0x58, // pop eax
		0x50, // push eax
		0x51, // push ecx
		0x52, // push edx
		0x68, INIT, INIT, INIT, INIT, // push offset pdLibName
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pImLoadLibrary
		0x85, 0xC0, // test eax, eax
		0x74, 0x0C, // jz
		0x68, INIT, INIT, INIT, INIT, // push offset pdProcName
		0x50, // push eax
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pdImGetProcAddress
		0xA3, INIT, INIT, INIT, INIT, // mov pdProcAddress, eax
		0x5A, // pop edx
		0x59, // pop ecx
		0x58, // pop eax
		INT3, NOP, //NOP, NOP, NOP // int3 and some padding
	};

	std::array<BYTE, AllocDataSize> data;
	static_assert(AllocData::CodeSize >= sizeof(cLoadLibrary));
	ApplyPatch(data.data(), cLoadLibrary);
	ApplyPatch(data.data() + 0x04, &GetData()->LibName);
	ApplyPatch(data.data() + 0x0A, pImLoadLibrary);
	ApplyPatch(data.data() + 0x13, &GetData()->ProcName);
	ApplyPatch(data.data() + 0x1A, pImGetProcAddress);
	ApplyPatch(data.data() + 0x1F, &GetData()->ProcAddress);
	ApplyPatch(data.data() + 0x2E, Database.GetDblInteractData().FinalAddr);
	PatchMem(pAlloc, data.data(), data.size());

	Log::WriteLine(__FUNCTION__ ": 载入代码位于 0x%08X", &GetData()->LoadLibraryFunc);

	// breakpoints for DLL loading and proc address retrieving
	bDLLsLoaded = false;
	bHooksCreated = false;
	loop_LoadLibrary = v_AllHooks.end();

	// set breakpoint
	Log::WriteLine(__FUNCTION__ ": 设置入口处的断点。");
	SetBP(pcEntryPoint);

	DEBUG_EVENT dbgEvent;
	ResumeThread(pInfo.hThread);

	bAVLogged = false;
	Log::WriteLine(__FUNCTION__ ": 开始调试循环。");
	auto exit_code = static_cast<DWORD>(-1);
	Log::Flush();

	for(;;)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		DWORD continueStatus = DBG_CONTINUE;
		bool wasBP = false;

		switch(dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			pInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
			pInfo.dwThreadId = dbgEvent.dwProcessId;
			pInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
			pInfo.dwThreadId = dbgEvent.dwThreadId;
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);
			CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			if(auto const it = Threads.find(dbgEvent.dwThreadId); it != Threads.end())
			{
				it->second.Thread.release();
				Threads.erase(it);
			}
			break;

		case EXCEPTION_DEBUG_EVENT:
			continueStatus = HandleException(dbgEvent);
			wasBP = (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(dbgEvent.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		if(dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
			exit_code = dbgEvent.u.ExitProcess.dwExitCode;
			break;
		} else if(dbgEvent.dwDebugEventCode == RIP_EVENT) {
			break;
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
	}

	CloseHandle(pInfo.hProcess);

	Log::WriteLine(
		__FUNCTION__ ": 正常退出，返回码：%X (%u).", exit_code, exit_code);
	Log::WriteLine();	
}

void SyringeDebugger::RemoveBP(LPVOID const address, bool const restoreOpcode)
{
	if(auto const i = Breakpoints.find(address); i != Breakpoints.end()) {
		if(restoreOpcode) {
			PatchMem(address, &i->second.original_opcode, 1);
		}

		Breakpoints.erase(i);
	}
}

void SyringeDebugger::RetrieveInfo()
{
	Database.Init(this);
	
	Log::WriteLine(
		__FUNCTION__ ": 正在从可执行文件 \"%s\" 中读入信息……", exe.c_str());

	try {
		PortableExecutable pe{ exe };
		auto const dwImageBase = pe.GetImageBase();

		ExeImageBase = dwImageBase;

		// creation time stamp
		dwTimeStamp = pe.GetPEHeader().FileHeader.TimeDateStamp;

		// entry point
		pcEntryPoint = reinterpret_cast<void*>(dwImageBase + pe.GetPEHeader().OptionalHeader.AddressOfEntryPoint);

		// get imports
		pImLoadLibrary = nullptr;
		pImGetProcAddress = nullptr;

		for(auto const& import : pe.GetImports()) {
			if(_strcmpi(import.Name.c_str(), "KERNEL32.DLL") == 0) {
				for(auto const& thunk : import.vecThunkData) {
					if(_strcmpi(thunk.Name.c_str(), "GETPROCADDRESS") == 0) {
						pImGetProcAddress = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					} else if(_strcmpi(thunk.Name.c_str(), "LOADLIBRARYA") == 0) {
						pImLoadLibrary = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					}
				}
			}
		}
	} catch(...) {
		Log::WriteLine(__FUNCTION__ ": 无法打开可执行文件 \"%s\"", exe.c_str());

		throw;
	}

	if(!pImGetProcAddress || !pImLoadLibrary) {
		Log::WriteLine(
			__FUNCTION__ ": 错误：无法载入 LoadLibraryA 和 GetProcAddress ！");

		throw_lasterror_or(ERROR_PROC_NOT_FOUND, exe);
	}

	// read meta information: size and checksum
	if(ifstream is{ exe, ifstream::binary }) {
		is.seekg(0, ifstream::end);
		dwExeSize = static_cast<DWORD>(is.tellg());
		is.seekg(0, ifstream::beg);

		CRC32 crc;
		char buffer[0x1000];
		while(auto const read = is.read(buffer, std::size(buffer)).gcount()) {
			crc.compute(buffer, read);
		}
		dwExeCRC = crc.value();
	}

	Log::WriteLine(__FUNCTION__ ": 成功载入可执行文件的信息。");
	Log::WriteLine("\t文件名：%s", exe.c_str());
	Log::WriteLine("\tLoadLibrary位于：0x%08X", pImLoadLibrary);
	Log::WriteLine("\tGetProcAddress位于：0x%08X", pImGetProcAddress);
	Log::WriteLine("\tEntryPoint位于：0x%08X", pcEntryPoint);
	Log::WriteLine("\t文件大小：0x%08X", dwExeSize);
	Log::WriteLine("\t文件CRC值：0x%08X", dwExeCRC);
	Log::WriteLine("\t载入时间戳：0x%08X", dwTimeStamp);
	Log::WriteLine();

	Log::WriteLine(__FUNCTION__ ": 打开 %s 以确定载入所需信息。", exe.c_str());
}

const std::string& ExecutableDirectoryPath()
{
	static std::string ss;
	if (!ss.empty())return ss;
	std::vector<char> full_path_exe(MAX_PATH);

	for (;;)
	{
		const DWORD result = GetModuleFileName(NULL,
			&full_path_exe[0],
			full_path_exe.size());

		if (result == 0)
		{
			// Report failure to caller. 
		}
		else if (full_path_exe.size() == result)
		{
			// Buffer too small: increase size. 
			full_path_exe.resize(full_path_exe.size() * 2);
		}
		else
		{
			// Success. 
			break;
		}
	}

	// Remove executable name. 
	std::string result(full_path_exe.begin(), full_path_exe.end());
	std::string::size_type i = result.find_last_of("\\/");
	if (std::string::npos != i) result.erase(i);

	ss = result;
	return ss;
}

std::vector<std::string> SimpleDLLs;


bool HammerPatchSimpleInterface_IsSimpleDLL(const std::string& AbsPath)
{
	if (auto const hLib = ModuleHandle(LoadLibrary(AbsPath.c_str()))) {
		if (auto const func = GetProcAddress(hLib, "HammerPatchSimpleInterface"))
		{
			Log::WriteLine(__FUNCTION__ ": 调用DLL： \"%s\" ...", AbsPath.c_str());
			FreeLibrary(hLib);
			return true;
		}
		else {
			//Log::WriteLine(__FUNCTION__ ": Not available.");
			FreeLibrary(hLib);
			return false;
		}
	}
	Log::WriteLine(__FUNCTION__ ": 无法打开DLL：\"%s\".", AbsPath.c_str());
	Log::WriteLine(__FUNCTION__ ": 错误码：%d.", GetLastError());
	return false;
}

void SyringeDebugger::FindDLLsLoop(const FindFile& file,const std::string& Path)
{
	std::string_view const fn(file->cFileName);
	std::string AbsPath = Path + "\\" + file->cFileName;
	std::string cfn = file->cFileName;
	for (auto& c : cfn)c = (char)::toupper(c);
	if (cfn == "SYRINGEEX.DLL")
	{
		Log::WriteLine(
			__FUNCTION__ ": 跳过 DLL ：\"%.*s\"", printable(fn));
		return;
	}
	//Log::WriteLine(
	//	__FUNCTION__ ": Potential DLL: \"%.*s\"", printable(fn));

	try {
		PortableExecutable DLL{ AbsPath };
		HookBuffer buffer;

		

		//Log::WriteLine(__FUNCTION__ ": Opening %s as a dll Handle : %08X", file->cFileName, (uint32_t)(FILE*)DLL.GetHandle());

		auto canLoad = false;
		if (auto const hooks = DLL.FindSection(".syhks00")) {
			canLoad = ParseHooksSection(DLL, *hooks, buffer);
		}
		else {
			canLoad = ParseInjFileHooks(AbsPath, buffer);
		}

		if (canLoad)
		{
			Log::WriteLine(
				__FUNCTION__ ": 已识别到 DLL：\"%.*s\"", printable(fn));
			Database.CreateLibData(DLL, fn, AbsPath);
			DLLs.push_back(AbsPath);
			DLLShort.emplace_back(fn);

			auto const jsf = AbsPath + ".json";
			auto& Ext = LibExt[AbsPath];
			Ext.ReadFromFile(jsf, AbsPath);
			if (Ext.Available())
			{
				Ext.PushDiasbleHooks(IdxSet);
			}
			for (auto& h : Ext.GetHooks())
			{
				auto eip = h.proc_address;
				h.proc_address = 0;
				buffer.add(eip, h);
			}
		}

		if (canLoad) {
			if (auto const res = Handshake(
				DLL.GetFilename(), static_cast<int>(buffer.count),
				buffer.checksum.value()))
			{
				canLoad = *res;
			}
			else if (auto const hosts = DLL.FindSection(".syexe00")) {
				canLoad = CanHostDLL(DLL, *hosts);
			}
		}

		if (canLoad) {
			for (auto const& it : buffer.hooks) {
				auto const eip = it.first;
				auto& h = Breakpoints[eip];
				h.p_caller_code.clear();
				h.original_opcode = 0x00;
				h.hooks.insert(
					h.hooks.end(), it.second.begin(), it.second.end());
			}
			for (auto const& it : buffer.hookExt) {
				auto const eip = it.first;
				auto& h = BreakpointRel[eip];
				h.p_caller_code.clear();
				h.original_opcode = 0x00;
				h.hooks.insert(
					h.hooks.end(), it.second.begin(), it.second.end());
			}
		}
		else if (!buffer.hooks.empty()) {
			Log::WriteLine(
				__FUNCTION__ ": DLL \"%.*s\" 中无法检测到钩子，停止载入",
				printable(fn));
		}
	}
	catch (...) {
		Log::WriteLine(
			__FUNCTION__ ": DLL \"%.*s\" 载入失败。", printable(fn));
	}
}

void SyringeDebugger::FindDLLs()
{
	/*
	for (auto file = FindFile((EDPath + "\\*.dll").c_str()); file; ++file) {
		std::string AbsPath = EDPath + "\\" + file->cFileName;
		if (HammerPatchSimpleInterface_IsSimpleDLL(AbsPath))
		{
			SimpleDLLs.push_back(AbsPath);
		}
		DLLs.push_back(AbsPath);
	}

	std::string EDPathAlt = EDPath + "\\Patches";
	for (auto file = FindFile((EDPath + "\\Patches\\*.dll").c_str()); file; ++file) {
		std::string AbsPath = EDPathAlt + "\\" + file->cFileName;
		if (HammerPatchSimpleInterface_IsSimpleDLL(AbsPath))
		{
			SimpleDLLs.push_back(AbsPath);
		}
		DLLs.push_back(AbsPath);
	}*/
	
	Breakpoints.clear();
	std::string EDPath = ExecutableDirectoryPath();

	
	Log::WriteLine(__FUNCTION__ ": 在目录 \"%s\" 中搜寻DLL。 ", ExecutableDirectoryPath().c_str());
	for(auto file = FindFile((EDPath + "\\*.dll").c_str()); file; ++file) {
		Log::WriteLine(__FUNCTION__ ": 正在检测 DLL \"%s\".", file->cFileName);
		FindDLLsLoop(file, EDPath);
	}

	std::string EDPathAlt = EDPath + "\\Patches";
	Log::WriteLine(__FUNCTION__ ": 在目录 \"%s\\Patches\"中搜寻DLL。", ExecutableDirectoryPath().c_str());
	for (auto file = FindFile((EDPath +"\\Patches\\*.dll").c_str()); file; ++file) {
		Log::WriteLine(__FUNCTION__ ": 正在检测 DLL \"%s\".", file->cFileName);
		FindDLLsLoop(file, EDPathAlt);
	}

	for (auto& p : Breakpoints )
	{
		std::sort(p.second.hooks.begin(), p.second.hooks.end(), [](const Hook& lh, Hook& rh) -> bool
			{
				if (lh.Priority != rh.Priority) return lh.Priority > rh.Priority;
				else return strcmp(lh.SubPriority, rh.SubPriority) > 0;
			});
	}
	IdxSet.Disable(GlobalDisableHooks);
	IdxSet.Enable(GlobalEnableHooks);



	// summarize all hooks
	v_AllHooks.clear();
	for(auto& it : Breakpoints) {
		for(auto& i : it.second.hooks) {

			if(IdxSet.Disabled({ i.lib,i.proc }))continue;
			std::string_view filename = i.lib;
			auto sz = filename.find_last_of('\\');
			auto sv = (sz != std::string_view::npos) ? filename.substr(sz + 1, filename.size() - sz - 1) : filename;
			if (ShowHookAnalysis)
			{
				if (InLibList(sv) && InAddrList((int)it.first))
					Analyzer.Add(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			}
			Analyzer.AddEx(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			v_AllHooks.push_back(&i);
		}
	}

	for (auto& it : BreakpointRel) {
		for (auto& i : it.second.hooks) {

			if (IdxSet.Disabled({ i.lib,i.proc }))continue;
			std::string_view filename = i.lib;
			auto sz = filename.find_last_of('\\');
			auto sv = (sz != std::string_view::npos) ? filename.substr(sz + 1, filename.size() - sz - 1) : filename;
			if (ShowHookAnalysis)
			{
				if (InLibList(sv) && InAddrList((int)it.first))
					Analyzer.Add(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			}
			Analyzer.AddEx(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));

		}
	}


	if (ShowHookAnalysis)
	{
		Log::WriteLine(__FUNCTION__ ": 正在输出钩子分析报告……", v_AllHooks.size());
		if (Analyzer.Report())Log::WriteLine(__FUNCTION__ ": 钩子分析报告已完成，详见 HookAnalysis.log 。", v_AllHooks.size());
		else Log::WriteLine(__FUNCTION__ ": 钩子分析报告生成失败。", v_AllHooks.size());
	}


	Log::WriteLine(__FUNCTION__ ": 载入完成，共添加 %d 个钩子。", v_AllHooks.size());
	Log::WriteLine();
}

//临时从老代码借来的XD，没优化
std::string CutSpace(const std::string& ss)//REPLACE ORIG
{
	auto fp = ss.find_first_not_of(" \011\r\n\t"), bp = ss.find_last_not_of(" \011\r\n\t");
	return std::string(ss.begin() + (fp == ss.npos ? 0 : fp),
		ss.begin() + (bp == ss.npos ? 0 : bp + 1));
}
std::vector<std::string> SplitParam(const std::string_view Text)//ORIG
{
	if (Text.empty())return {};
	size_t cur = 0, crl;
	std::vector<std::string> ret;
	while ((crl = Text.find_first_of(',', cur)) != Text.npos)
	{
		ret.push_back(CutSpace(std::string(Text.begin() + cur, Text.begin() + crl)));
		cur = crl + 1;
	}
	ret.push_back(CutSpace(std::string(Text.begin() + cur, Text.end())));
	return ret;
}


bool SyringeDebugger::ParseInjFileHooks(
	std::string_view const lib, HookBuffer& hooks)
{
	auto const inj = std::string(lib) + ".inj";
	static char Buf[10086];

	if(auto const file = FileHandle(_fsopen(inj.c_str(), "r", _SH_DENYWR))) {
		constexpr auto Size = 0x100;
		char line[Size];
		while(fgets(line, Size, file)) {
			if(*line != ';' && *line != '\r' && *line != '\n') {
				void* eip = nullptr;
				size_t n_over = 0u;
				int pr;

				// parse the line (length is optional, defaults to 0)
				if(sscanf_s(
					line, "%p = %[^\t;\r\n]", &eip, Buf, 10000) == 2)
				{
					auto vec = SplitParam(Buf);
					//0:func %s 1:n_over %x 2:priority %d 3: sub_priority %s
					if (vec.size() >= 2)
					{
						sscanf_s(vec[1].c_str(), "%x", &n_over);
						if (vec.size() >= 3)
						{
							sscanf_s(vec[2].c_str(), "%d", &pr);
							if (vec.size() >= 4)
							{
								hooks.add(eip, lib, vec[0].c_str(), n_over, pr, vec[3].c_str(),"");
							}
							else
							{
								hooks.add(eip, lib, vec[0].c_str(), n_over, pr, "", "");
							}
						}
						else
						{
							hooks.add(eip, lib, vec[0].c_str(), n_over, 100000, "", "");
						}
					}
				}
			}
		}

		return true;
	}

	return false;
}

bool SyringeDebugger::CanHostDLL(
	PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const
{
	constexpr auto const Size = sizeof(hostdecl);
	auto const base = DLL.GetImageBase();

	auto const begin = hosts.PointerToRawData;
	auto const end = begin + hosts.SizeOfRawData;

	std::string hostName;
	for(auto ptr = begin; ptr < end; ptr += Size) {
		hostdecl h;
		if(DLL.ReadBytes(ptr, Size, &h)) {
			if(h.hostNamePtr) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hostNamePtr - base);
				if(DLL.ReadCString(rawNamePtr, hostName)) {
					hostName += ".exe";
					if(!_strcmpi(hostName.c_str(), exe.c_str())) {
						return true;
					}
				}
			}
		} else {
			break;
		}
	}
	return false;
}

bool SyringeDebugger::ParseHooksSection(
	PortableExecutable& DLL, IMAGE_SECTION_HEADER const& hooks,
	HookBuffer& buffer)
{
	//Log::WriteLine(__FUNCTION__ ": Executing");

	constexpr auto const Size = sizeof(hookdecl);
	auto const base = DLL.GetImageBase();
	auto const filename = std::string_view(DLL.GetFilename());

	
	auto const begin = hooks.PointerToRawData;
	auto const end = begin + hooks.SizeOfRawData;

	std::string hookName,hookSub;
	for(auto ptr = begin; ptr < end; ptr += Size) {
		hookdecl h;
		if(DLL.ReadBytes(ptr, Size, &h)) {
			// msvc linker inserts arbitrary padding between variables that come
			// from different translation units

			//Log::WriteLine(__FUNCTION__ ": Hook: Addr %08X Size %d HookNamePtr %08X",h.hookAddr,h.hookSize,h.hookNamePtr);
			if(h.hookNamePtr) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
				if(DLL.ReadCString(rawNamePtr, hookName)) {
					//Log::WriteLine(__FUNCTION__ ": \t\tName \"%s\"", hookName.c_str());
					buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, 100000, "", "");
				}
			}
		} else {
			Log::WriteLine(__FUNCTION__ ": 从 \"%s\" 中插入钩子时发生故障", DLL.GetFilename());
			return false;
		}
	}


	auto const hookalt = DLL.FindSection(".hphks00");
	if (hookalt)
	{
		auto const beginalt = hookalt->PointerToRawData;
		auto const endalt = begin + hookalt->SizeOfRawData;
		constexpr auto const SizeAlt = sizeof(hookdecl);

		for (auto ptr = beginalt; ptr < endalt; ptr += SizeAlt) {
			hookaltdecl h;
			if (DLL.ReadBytes(ptr, SizeAlt, &h)) {
				//Log::WriteLine(__FUNCTION__ ": Hook: Addr %08X Size %d HookNamePtr %08X Priority %d SubPrioriyPtr %08X", h.hookAddr, h.hookSize, h.hookNamePtr, h.Priority, h.SubPriorityPtr);
				if (h.hookNamePtr) {
					auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
					if (DLL.ReadCString(rawNamePtr, hookName)) {
						//Log::WriteLine(__FUNCTION__ ": \t\tName \"%s\"", hookName.c_str());
						if (h.SubPriorityPtr)
						{
							if (DLL.ReadCString(DLL.VirtualToRaw(h.SubPriorityPtr - base), hookSub))
							{
								buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, hookSub, "");
							}
							else buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, "", "");
						}
						else buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, "", "");
					}
				}
			}
			else {
				Log::WriteLine(__FUNCTION__ ": 从 \"%s\" 中插入钩子时发生故障", DLL.GetFilename());
				return false;
			}
		}
	}

	return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.

struct SyringeSimpleDLLInfo
{
	using PathBuf = char[300];
	size_t cbSize;
	int NPathBuf;
	PathBuf* Bufs;
};

using SYRINGEGETSIMPLEDLLLISTFUNC = HRESULT(__cdecl*)(SyringeSimpleDLLInfo*);

std::optional<bool> SyringeDebugger::Handshake(
	char const* const lib, int const hooks, unsigned int const crc)
{
	std::optional<bool> ret;

	if(auto const hLib = ModuleHandle(LoadLibrary(lib))) {
		if(auto const func = reinterpret_cast<SYRINGEHANDSHAKEFUNC>(
			GetProcAddress(hLib, "SyringeHandshake")))
		{
			Log::WriteLine(__FUNCTION__ ": 在Syringe.exe的进程空间中与DLL通讯： \"%s\" 。", lib);
			constexpr auto Size = 0x100u;
			std::vector<char> buffer(Size + 1); // one more than we tell the dll

			auto const shInfo = std::make_unique<SyringeHandshakeInfo>();
			shInfo->cbSize = sizeof(SyringeHandshakeInfo);
			shInfo->num_hooks = hooks;
			shInfo->checksum = crc;
			shInfo->exeFilesize = dwExeSize;
			shInfo->exeTimestamp = dwTimeStamp;
			shInfo->exeCRC = dwExeCRC;
			shInfo->cchMessage = static_cast<int>(Size);
			shInfo->Message = buffer.data();

			if(auto const res = func(shInfo.get()); SUCCEEDED(res)) {
				buffer.back() = 0;
				Log::WriteLine(
					__FUNCTION__ ": 返回信息： \"%s\" (%X)", buffer.data(), res);
				ret = (res == S_OK);
			} else {
				// don't use any properties of shInfo.
				Log::WriteLine(__FUNCTION__ ": 调取失败。 (%X)", res);
				ret = false;
			}
		} else {
			//Log::WriteLine(__FUNCTION__ ": Not available.");
		}
	}
	return ret;
}
/*
bool SyringeReceive(char const* const lib)
{
	if (auto const hLib = ModuleHandle(LoadLibrary(lib))) {
		if (auto const func = reinterpret_cast<SYRINGEGETSIMPLEDLLLISTFUNC>(
			GetProcAddress(hLib, "SyringeReceiveSimpleDllList")))
		{
			Log::WriteLine(__FUNCTION__ ": Calling \"%s\" ...", lib);
			constexpr auto Size = 0x100u;
			std::vector<char> buffer(Size + 1); // one more than we tell the dll

			auto const shInfo = std::make_unique<SyringeSimpleDLLInfo>();
			shInfo->cbSize = sizeof(SyringeHandshakeInfo);
			shInfo->NPathBuf = SimpleDLLs.size();
			shInfo->Bufs = new SyringeSimpleDLLInfo::PathBuf[SimpleDLLs.size()]();
			for (size_t i = 0; i < SimpleDLLs.size(); i++)
			{
				strcpy_s(shInfo->Bufs[i], SimpleDLLs[i].c_str());
			}

			if (auto const res = func(shInfo.get()); SUCCEEDED(res)) {
				buffer.back() = 0;
				Log::WriteLine(
					__FUNCTION__ ": Receive DLL List (Size %u)", SimpleDLLs.size());
			}
			else {
				// don't use any properties of shInfo.
				Log::WriteLine(__FUNCTION__ ": Failed To Receive DLL List (Size %u)", SimpleDLLs.size());
			}
			delete[] shInfo->Bufs;
			return true;
		}
		else {
			//Log::WriteLine(__FUNCTION__ ": Not available.");
			return false;
		}
	}
	return false;
}
*/