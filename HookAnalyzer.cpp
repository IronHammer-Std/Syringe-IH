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
	fprintf(File, "%s ��������ȡ���Ĺ��ӡ�\n", VersionString);
	if (ShowHookAnalysis_ByAddr)
	{
		fputs("========================\n", File);
		fputs("���չ���λ�÷�������ÿ����ַ�����չ���ִ����\n", File);
		for (auto& p : ByAddress)
		{
			fprintf(File, "�� %08X ��\n", p.first);
			for (auto v : p.second)
			{
				fprintf(File, "����\"%s�������\"%s\"������\"%s\"������%d�����ȼ� %d�������ȼ� \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
			}
		}
	}
	
	if (ShowHookAnalysis_ByLib)
	{
		fputs("========================\n", File);
		fputs("���չ�����Դ������\n", File);
		for (auto& p : ByLibName)
		{
			fprintf(File, "���ڷ��� DLL ��\"%s\" ����\n", p.first.c_str());
			for (auto v : p.second)
			{
				fprintf(File, "����\"%s\"�������\"%s\"��λ��%08X������%d�����ȼ� %d�������ȼ� \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Addr, v.Len, v.Priority, v.SubPriority.c_str());
			}
		}
	}
	
	fputs("========================\n", File);
	fprintf(File, "%s ������ϡ�\n", VersionString);
	return true;
}