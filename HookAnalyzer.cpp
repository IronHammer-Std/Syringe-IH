#include "HookAnalyzer.h"
#include "Handle.h"
#include "Setting.h"

void PrintTimeStampToFile(const FileHandle& File);

void HookAnalyzer::Add(HookAnalyzeData&& Data)
{
	ByLibName[Data.Lib].push_back(Data);
	HookMap[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
	ByAddress[Data.Addr].push_back(std::move(Data));
}
void HookAnalyzer::AddEx(HookAnalyzeData&& Data)
{
	HookMapEx[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
	ByAddressEx[Data.Addr].push_back(std::move(Data));
}
bool HookAnalyzer::Report()
{
	FileHandle File = FileHandle(fopen("HookAnalysis.log", "w"));
	if (!File)return false;
	fprintf(File, "%s 将分析获取到的钩子。\n", VersionString);
	if (ShowHookAnalysis_ByAddr)
	{
		fputs("========================\n", File);
		fputs("按照钩子位置分析：（每个地址处按照钩子执行序）\n", File);
		for (auto& p : ByAddress)
		{
			fprintf(File, "在 %08X ：\n", p.first);
			for (auto v : p.second)
			{
				fprintf(File, "钩子\"%s，相对于\"%s\"，来自\"%s\"，长度%d，优先级 %d，次优先级 \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
			}
		}
	}
	
	if (ShowHookAnalysis_ByLib)
	{
		fputs("========================\n", File);
		fputs("按照钩子来源分析：\n", File);
		for (auto& p : ByLibName)
		{
			fprintf(File, "正在分析 DLL ：\"%s\" ……\n", p.first.c_str());
			for (auto v : p.second)
			{
				fprintf(File, "钩子\"%s\"，相对于\"%s\"，位于%08X，长度%d，优先级 %d，次优先级 \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Addr, v.Len, v.Priority, v.SubPriority.c_str());
			}
		}
	}
	
	fputs("========================\n", File);
	fprintf(File, "%s 分析完毕。\n", VersionString);
	return true;
}