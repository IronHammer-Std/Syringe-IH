#pragma once

#include "Setting.h"
#include "Handle.h"
#include <vector>
#include <memory>
#include <unordered_map>
#include <string_view>

class SyringeDebugger;
class PortableExecutable;
struct MemCopyInfo;

DWORD QuickHashCStr(const char* str);
DWORD QuickHashCStrUpper(const char* str);

struct RemoteDataHeader
{
	int Size;
	int NLib;
	int NAddr;
	int NHook;
	int NMem;

	int ExeDataOffset;
	int LibDataListOffset;
	int AddrDataListOffset;
	int HookDataListOffset;
	int CopyMemListOffset;
	int dwReserved[22];
};
static_assert(sizeof(RemoteDataHeader) == 128);

struct ExeRemoteData
{
	char SyringeVersionStr[256];
	BYTE VMajor;
	BYTE VMinor;
	BYTE VRelease;
	BYTE VBuild;
	
	char FileName[260];
	char AbsPath[260];
	DWORD BaseAddress;
	DWORD EntryPoint;
};
struct LibRemoteData
{
	struct
	{
		char* LibName;
		char* AbsPath;
		DWORD ID;//QuickHash of AbsPath
	}Base;

	std::string LibName;
	std::string AbsPath;
};
struct AddrRemoteData
{
	struct
	{
		DWORD Addr;
		int HookCount;
		//DWORD FirstHookIndex;//VLA Header
	}Base;

	std::vector<DWORD> HookID;
};
struct HookRemoteData
{
	struct
	{
		char* ProcName;
		//char* LibName;
		DWORD HookID;
		DWORD LibID;
		DWORD HookAddress;
		size_t OverrideLength;
	}Base;

	std::string ProcName;
	//std::string LibName;
};

struct MemCopyData
{
	char* Name;
	void* Addr;
};

class TempByteStream
{
private:
	std::vector<BYTE> Buffer;
public:
	template<typename T>
	size_t Push(const T& Data, size_t ExtBytes)//返回写入的头偏移量
	{
		auto pData = (const BYTE*)&Data;
		auto sz = Buffer.size();
		Buffer.resize(sz + sizeof(T)+ ExtBytes);
		memcpy((void*)(Buffer.data() + sz), pData, sizeof(T) + ExtBytes);
		return sz;
	}

	size_t PushBytes(const BYTE* Data, size_t Count)//返回写入的头偏移量
	{
		auto sz = Buffer.size();
		Buffer.resize(sz + Count);
		memcpy((void*)(Buffer.data() + sz), Data, Count);
		return sz;
	}

	size_t PushZero(size_t Count)
	{
		auto sz = Buffer.size();
		Buffer.resize(sz + Count);
		return sz;
	}

	void Clear()
	{
		Buffer.clear();
	}

	const BYTE* Data() const;
	BYTE* Offset(int Ofs) const;
	size_t Size() const;
};

struct DoubleInteractData
{
	struct TransferData
	{
		DWORD PEB_Base;
		int dwReserved[15];
	}Transfer;
	DWORD FinalAddr;
	size_t FinalOffset;

	inline TransferData* RemotePtr()
	{
		return reinterpret_cast<TransferData*>(FinalAddr);
	}
};

struct CopyRange
{
	DWORD Begin;
	DWORD End;
	MemCopyInfo* ptr;
};

class RemoteDatabase
{
private:
	VirtualMemoryHandle Mem;
	TempByteStream Stm;
	SyringeDebugger* Dbg;

	std::unique_ptr<ExeRemoteData> Exe;
	std::vector<LibRemoteData> Lib;
	std::vector<AddrRemoteData> Addr;
	std::vector<HookRemoteData> Hook;
	std::unordered_map<DWORD, std::string_view> StrList;
	std::unordered_map<DWORD, DWORD> OfsList;
	std::unordered_map<DWORD, DWORD> NegOfsList;
	std::unordered_map<std::string, DWORD> CopyList;
	std::vector<MemCopyInfo> CopyAll;
	std::unordered_map<std::string, CopyRange> CopyRangeList;

	DWORD RemoteDBStart, RemoteDBEnd;
	DoubleInteractData Interact;
public:
	DoubleInteractData& GetDblInteractData()
	{
		return Interact;
	}

	inline void Init(SyringeDebugger* p)
	{
		Dbg = p;
	}

	template<typename T>
	size_t Push(const T& Data,size_t ExtBytes = 0)//返回写入的头偏移量
	{
		return Stm.Push(Data, ExtBytes);
	}

	inline size_t PushZero(size_t Count)
	{
		return Stm.PushZero(Count);
	}
	inline size_t PushBytes(const BYTE* Data, size_t Count)
	{
		return Stm.PushBytes(Data, Count);
	}

	template<typename T>
	T& Offset(int Ofs)
	{
		return *reinterpret_cast<T*>(Stm.Offset(Ofs));
	}


	void WriteToStream();
	void CreateData();
	void PushString();
	void ResetPointer(DWORD BaseAddr);
	void CreateLibData(const PortableExecutable& DLL, std::string_view cname, std::string_view abs);
	size_t CopyAndPush(DWORD Start, DWORD End);
	void CopyAndPush(const std::vector<MemCopyInfo>&);
	void CopyAndPushEnd();



	//RUNTIME
	void SendData();
	void Dump();

	inline bool InRange(DWORD RemoteAddr)
	{
		if (!RemoteDBStart)return false;
		if (!RemoteDBEnd)return false;
		return (RemoteDBStart <= RemoteAddr) && (RemoteAddr < RemoteDBEnd);
	}

	MemCopyInfo* GetCopyMemName(DWORD RemoteAddr);
	std::pair<DWORD, std::string> AnalyzeDBAddr(DWORD RemoteAddr);
};


void RemoteBuf_Load(SyringeDebugger* Dbg, void* Addr, void* Buffer, size_t Size);

template<typename T>
class RemoteBuf
{
	SyringeDebugger* Dbg;
	void* Addr;
	T Buffer;
public:
	RemoteBuf() = delete;
	RemoteBuf(SyringeDebugger* pDbg) :Dbg(pDbg), Addr(nullptr), Buffer(){}
	RemoteBuf(SyringeDebugger* pDbg,T* Address) :Dbg(pDbg), Addr((void*)Address), Buffer() {}

	RemoteBuf& operator=(T* Ptr)
	{
		Addr = Ptr;
		return *this;
	}

	T& operator*()
	{
		RemoteBuf_Load(Dbg, Addr, &Buffer, sizeof(T));
		return Buffer;
	}
};

template<typename T>
class RemoteArrayBuf
{
	SyringeDebugger* Dbg;
	void* Addr;
	T* Buffer;
public:
	RemoteArrayBuf() = delete;
	RemoteArrayBuf(SyringeDebugger* pDbg) :Dbg(pDbg), Addr(nullptr), Buffer(nullptr) {}
	RemoteArrayBuf(SyringeDebugger* pDbg, T* Address) :Dbg(pDbg), Addr((void*)Address), Buffer(nullptr) {}

	RemoteArrayBuf& operator=(T* Ptr)
	{
		Addr = Ptr;
		return *this;
	}

	T* operator()(size_t N)
	{
		if (Buffer)delete[]Buffer;
		Buffer = new T(N);
		RemoteBuf_Load(Dbg, Addr, &Buffer, sizeof(T)*N);
		return Buffer;
	}

	T& operator[](size_t Idx)
	{
		return Buffer[Idx];
	}
};

template<typename T>
T& AnyOffset(void* ptr, size_t offset)
{
	return *((T*)(((char*)ptr) + offset));
}

template<typename T>
T* AnyOffsetPtr(void* ptr, size_t offset)
{
	return (T*)(((char*)ptr) + offset);
}

