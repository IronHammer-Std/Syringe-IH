#pragma once
#include <string>
#include <vector>
#include "ExtFunc.h"




struct BytePointerArray
{
	int N;
	uint8_t* Data;
};


void ReadSetting();
std::string GetStringFromFile(const char* FileName);
bool InLibList(std::string_view Lib);
bool InAddrList(int Addr);

extern bool ShowHookAnalysis;
extern bool ShowHookAnalysis_ByLib;
extern bool ShowHookAnalysis_ByAddr;
extern std::vector<int> AddrRestriction;
extern std::vector<std::string> LibRestriction;

extern bool RunningYR;
extern bool RemoteDatabaseDump;

extern std::set<HookIdx> GlobalDisableHooks;
extern std::set<HookIdx> GlobalEnableHooks;


extern std::string DefaultExecName;
extern std::string DefaultCmdLine;

constexpr auto const VersionString = "Syringe 0.7.2.1";
const int VMajor = 0;
const int VMinor = 7;
const int VRelease = 2;
const int VBuild = 1;
