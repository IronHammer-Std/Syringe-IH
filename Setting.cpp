#include "Setting.h"
#include "ExtJson.h"
#include "Handle.h"
#include "Log.h"

bool ShowHookAnalysis = false;
std::string DefaultExecName;
std::string DefaultCmdLine;
bool ShowHookAnalysis_ByLib = false;
bool ShowHookAnalysis_ByAddr = false;
std::vector<int> AddrRestriction;
std::vector<std::string> LibRestriction;
bool RunningYR = false;
bool RemoteDatabaseDump = false;

std::set<HookIdx> GlobalDisableHooks;
std::set<HookIdx> GlobalEnableHooks;

std::string GetStringFromFile(const char* FileName)
{
    FileHandle File(fopen(FileName, "r"));
    if (!File)return "";
    fseek(File, 0, SEEK_END);
    auto Pos = ftell(File);
    char* FileStr;
    FileStr = new char[Pos + 50];
    if (FileStr == nullptr)return "";
    fseek(File, 0, SEEK_SET);
    fread(FileStr, 1, Pos, File);
    FileStr[Pos] = 0;

    std::string LoadStr = FileStr;
    delete[]FileStr;
    return LoadStr;
}

bool InLibList(std::string_view Lib)
{
    if (LibRestriction.empty())return true;
    for (auto& s : LibRestriction)
    {
        if (Lib == s)return true;
    }
    return false;
}

bool InAddrList(int Addr)
{
    if (AddrRestriction.empty())return true;
    for (size_t i = 0; i < AddrRestriction.size() >> 1; i++)
    {
        if (AddrRestriction[i << 1] < Addr &&
            Addr < AddrRestriction[i << 1 | 1])return true;
    }
    return false;
}

void ReadSetting()
{
    Log::WriteLine("正在从 Syringe.json 中载入配置……");
    auto Str = GetStringFromFile("Syringe.json");
    if (Str.empty())
    {
        Log::WriteLine("载入 Syringe.json 失败：无法读取配置文件。");
        Log::WriteLine("回退到默认配置。");
        return;
    }
    JsonFile File;
    File.Parse(Str);
    if (!File.Available())
    {
        Log::WriteLine("载入 Syringe.json 失败：非法的 JSON 文件");
        Log::WriteLine("回退到默认配置。");
        return;
    }

    auto Obj = File.GetObj();
    auto SObj = Obj.GetObjectItem("HookAnalysis");
    if (SObj.Available())
    {
        if (SObj.IsTypeBool())
        {
            ShowHookAnalysis = SObj.GetBool();
            Log::WriteLine("HookAnalysis = %s", CStrBoolImpl(ShowHookAnalysis, StrBoolType::Str_true_false));
            ShowHookAnalysis_ByLib = ShowHookAnalysis;
            ShowHookAnalysis_ByAddr = ShowHookAnalysis;
        }
        else if (SObj.IsTypeObject())
        {
            auto TObj = SObj.GetObjectItem("ByLibrary");
            if (TObj.Available() && TObj.IsTypeBool())
            {
                ShowHookAnalysis_ByLib = TObj.GetBool();
            }
            TObj = SObj.GetObjectItem("ByAddress");
            if (TObj.Available() && TObj.IsTypeBool())
            {
                ShowHookAnalysis_ByAddr = TObj.GetBool();
            }
            ShowHookAnalysis = ShowHookAnalysis_ByLib || ShowHookAnalysis_ByAddr;
            Log::WriteLine("HookAnalysis = %s", CStrBoolImpl(ShowHookAnalysis, StrBoolType::Str_true_false));
            Log::WriteLine("\tByLibrary = %s", CStrBoolImpl(ShowHookAnalysis_ByLib, StrBoolType::Str_true_false));
            Log::WriteLine("\tByAddress = %s", CStrBoolImpl(ShowHookAnalysis_ByAddr, StrBoolType::Str_true_false));
            TObj = SObj.GetObjectItem("LibraryRange");
            Log::WriteLine("\tAddressRange : ");
            if (TObj.Available() && TObj.IsTypeArray())
            {
                for (auto& obj : TObj.GetArrayObject())
                {
                    if (obj.Available() && obj.IsTypeArray())
                    {
                        auto arr = obj.GetArrayString();
                        if (arr.size() >= 2)
                        {
                            auto sz = AddrRestriction.size();
                            AddrRestriction.resize(AddrRestriction.size() + 2);
                            sscanf(arr[0].c_str(), "%X", &AddrRestriction[sz]);
                            sscanf(arr[1].c_str(), "%X", &AddrRestriction[sz + 1]);
                            Log::WriteLine("\t\t%08X ~ %08X", AddrRestriction[sz], AddrRestriction[sz + 1]);
                        }
                    }
                }
            }
            Log::WriteLine("\tLibraryRange : ");
            TObj = SObj.GetObjectItem("LibraryRange");
            if (TObj.Available() && TObj.IsTypeArray())
            {
                LibRestriction = std::move(TObj.GetArrayString());
                for (auto& s : LibRestriction)
                {
                    Log::WriteLine("\t\t%s", s.c_str());
                }
            }
        }
    }
    SObj = Obj.GetObjectItem("DefaultExecutableName");
    if (SObj.Available() && SObj.IsTypeString())
    {
        DefaultExecName = SObj.GetString();
        Log::WriteLine("DefaultExecutableName = \"%s\"", DefaultExecName.c_str());
    }
    SObj = Obj.GetObjectItem("DefaultCommandLine");
    if (SObj.Available() && SObj.IsTypeString())
    {
        DefaultCmdLine = SObj.GetString();
        Log::WriteLine("DefaultCommandLine = \"%s\"", DefaultCmdLine.c_str());
    }
    SObj = Obj.GetObjectItem("IsRunningYR");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        RunningYR = SObj.GetBool();
        Log::WriteLine("IsRunningYR = \"%s\"", CStrBoolImpl(RunningYR, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("RemoteDatabaseDump");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        RemoteDatabaseDump = SObj.GetBool();
        Log::WriteLine("RemoteDatabaseDump = \"%s\"", CStrBoolImpl(RemoteDatabaseDump, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("DisableHooks");
    if (SObj.Available() && SObj.IsTypeObject())
    {
        ReadHookIdxSet(GlobalDisableHooks, SObj);
        //LogIdxSet(GlobalDisableHooks, "GlobalDisableHooks");
    }
    SObj = Obj.GetObjectItem("EnableHooks");
    if (SObj.Available() && SObj.IsTypeObject())
    {
        ReadHookIdxSet(GlobalEnableHooks, SObj);
        //LogIdxSet(GlobalEnableHooks, "GlobalEnableHooks");
    }
    Log::WriteLine("成功载入配置。");
}