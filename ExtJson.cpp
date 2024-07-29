#include "ExtJson.h"
#ifdef IHCore
#include "ExtFile.h"
#include "ExtLog.h"
#endif

bool _IH_IsTrueString(const std::string& s1)
{
    return s1 == "true" || s1 == "yes" || s1 == "1" || s1 == "T" || s1 == "True" || s1 == "Yes" || s1 == "t" || s1 == "Y" || s1 == "y";
}

std::vector<int> cJSON_GetVectorInt(cJSON* Array)
{
    int N = cJSON_GetArraySize(Array);
    cJSON* Item = cJSON_GetArrayItem(Array, 0);
    std::vector<int> Ret;
    Ret.reserve(N);
    for (int i = 0; i < N; i++)
    {
        Ret.push_back(Item->valueint);
        Item = Item->next;
    }
    return Ret;
}
std::vector<uint8_t> cJSON_GetVectorBool(cJSON* Array)
{
    int N = cJSON_GetArraySize(Array);
    cJSON* Item = cJSON_GetArrayItem(Array, 0);
    std::vector<uint8_t> Ret;
    Ret.reserve(N);
    for (int i = 0; i < N; i++)
    {
        Ret.push_back(((Item->type & 0xFF) == cJSON_True) ? true : false);
        Item = Item->next;
    }
    return Ret;
}
std::vector<std::string> cJSON_GetVectorString(cJSON* Array)
{
    int N = cJSON_GetArraySize(Array);
    cJSON* Item = cJSON_GetArrayItem(Array, 0);
    std::vector<std::string> Ret;
    Ret.reserve(N);
    for (int i = 0; i < N; i++)
    {
        Ret.push_back(Item->valuestring);
        Item = Item->next;
    }
    return Ret;
}
std::vector<cJSON*> cJSON_GetVectorObject(cJSON* Array)
{
    int N = cJSON_GetArraySize(Array);
    cJSON* Item = cJSON_GetArrayItem(Array, 0);
    std::vector<cJSON*> Ret;
    Ret.reserve(N);
    for (int i = 0; i < N; i++)
    {
        Ret.push_back(Item);
        Item = Item->next;
    }
    return Ret;
}
void cJson_SwapData(cJSON* A, cJSON* B)
{
    if (A == nullptr || B == nullptr)return;
    std::swap(*A, *B);
}

#define ____GET____  auto Obj = GetObjectItem(Str)
int JsonObject::ItemInt(const std::string& Str) const { ____GET____; return Obj.GetInt(); }
double JsonObject::ItemDouble(const std::string& Str) const { ____GET____; return Obj.GetDouble(); }
std::string JsonObject::ItemString(const std::string& Str) const { ____GET____; return Obj.GetString(); }
const char* JsonObject::ItemCString(const std::string& Str) const { ____GET____; return Obj.GetCString(); }
bool JsonObject::ItemBool(const std::string& Str) const { ____GET____; return Obj.GetBool(); }
bool JsonObject::ItemStrBool(const std::string& Str) const { ____GET____; return Obj.GetStrBool(); }
size_t JsonObject::ItemArraySize(const std::string& Str) const { ____GET____; return Obj.GetArraySize(); }
std::vector<int> JsonObject::ItemArrayInt(const std::string& Str) const { ____GET____; return Obj.GetArrayInt(); }
std::vector<uint8_t> JsonObject::ItemArrayBool(const std::string& Str) const { ____GET____; return Obj.GetArrayBool(); }
std::vector<std::string> JsonObject::ItemArrayString(const std::string& Str) const { ____GET____; return Obj.GetArrayString(); }
std::vector<JsonObject> JsonObject::ItemArrayObject(const std::string& Str) const { ____GET____; return Obj.GetArrayObject();}
#undef ____GET____

JsonObject JsonObject::GetObjectItem(const std::string& Str) const
{
    auto pObj = cJSON_GetObjectItem(Object, Str.c_str());
/*
    if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::GetObjectItem <- std::string Str=%s", Str.c_str());
        GlobalLogB.AddLog(LogBufB);
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::GetObjectItem : Object Data : \n\"%s\"", GetText().c_str());
        GlobalLogB.AddLog(LogBufB);
    }
*/
    return { pObj }; 
}

std::string JsonObject::GetText() const
{
    char* CStr = cJSON_Print(Object);
    std::string Str = CStr;
    cJSON_Free(CStr);
    return Str;
}

std::vector<JsonObject> JsonObject::GetArrayObject() const
{
    int N = cJSON_GetArraySize(Object);
    cJSON* Item = cJSON_GetArrayItem(Object, 0);
    std::vector<JsonObject> Ret;
    Ret.reserve(N);
    for (int i = 0; i < N; i++)
    {
        Ret.push_back(JsonObject{ Item });
        Item = Item->next;
    }
    return Ret;
}

std::unordered_map<std::string, JsonObject> JsonObject::GetMapObject() const
{
    std::unordered_map<std::string, JsonObject> Ret;
    JsonObject Node = GetChildItem();
    while (Node.Available())
    {
        Ret.insert({ Node.GetName(),Node });
        Node = Node.GetNextItem();
    }
    return Ret;
}
std::unordered_map<std::string, double> JsonObject::GetMapDouble() const
{
    std::unordered_map<std::string, double> Ret;
    JsonObject Node = GetChildItem();
    while (Node.Available())
    {
        Ret.insert({ Node.GetName(),Node.GetDouble() });
        Node = Node.GetNextItem();
    }
    return Ret;
}
std::unordered_map<std::string, int> JsonObject::GetMapInt() const
{
    std::unordered_map<std::string, int> Ret;
    JsonObject Node = GetChildItem();
    while (Node.Available())
    {
        Ret.insert({ Node.GetName(),Node.GetInt() });
        Node = Node.GetNextItem();
    }
    return Ret;
}
std::unordered_map<std::string, bool> JsonObject::GetMapBool() const
{
    std::unordered_map<std::string, bool> Ret;
    JsonObject Node = GetChildItem();
    while (Node.Available())
    {
        Ret.insert({ Node.GetName(),Node.GetBool() });
        Node = Node.GetNextItem();
    }
    return Ret;
}
std::unordered_map<std::string, std::string> JsonObject::GetMapString() const
{
    std::unordered_map<std::string, std::string> Ret;
    JsonObject Node = GetChildItem();
    while (Node.Available())
    {
        Ret.insert({ Node.GetName(),Node.GetString() });
        Node = Node.GetNextItem();
    }
    return Ret;
}

void JsonFile::Parse(std::string Str)
{
    /*
    if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::Parse <- std::string Str=%s", Str.c_str()); GlobalLogB.AddLog(LogBufB);
    }
    */
    cJSON_Minify(Str.data());
    Clear();
    File = cJSON_Parse(Str.data());
}
void JsonFile::ParseWithOpts(std::string Str, const char** ReturnParseEnd, int RequireNullTerminated)
{
    /*
    if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::ParseWithOpts <- std::string Str=%s, int RequireNullTerminated=%d", Str.c_str(), RequireNullTerminated); GlobalLogB.AddLog(LogBufB);
    }
    */
    cJSON_Minify(Str.data());
    Clear();
    File = cJSON_ParseWithOpts(Str.data(), ReturnParseEnd, RequireNullTerminated);
}
#ifdef IHCore
void JsonFile::ParseFromFile(const char* FileName)
{
    /*
    if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::ParseFromFile <- char* FileName=%s", FileName); GlobalLogB.AddLog(LogBufB);
    }
    */
    Clear();

    ExtFileClass Fp;
    if (!Fp.Open(FileName, "r"))return;
    Fp.Seek(0, SEEK_END);
    int Pos = Fp.Position();
    char* FileStr;
    FileStr = new char[Pos + 50];
    if (FileStr == nullptr)return;
    Fp.Seek(0, SEEK_SET);
    Fp.Read(FileStr, 1, Pos);
    FileStr[Pos] = 0;
    Fp.Close();

    int iPos = 0;
    while (FileStr[iPos] != '{' && iPos < Pos)iPos++;
    if (iPos == Pos) { delete[]FileStr; return; }

    cJSON_Minify(FileStr + iPos);
    File = cJSON_Parse(FileStr + iPos);
    /*
    if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        GlobalLogB.AddLog("JsonFile::ParseFromFile �� JSON�ı���");
        GlobalLogB.AddLog_CurTime(false);
        GlobalLogB.AddLog("\"", false);
        GlobalLogB.AddLog(UTF8toANSI(FileStr + iPos).c_str(), false);
        GlobalLogB.AddLog("\"");
    }*/

    delete[]FileStr;
}

void JsonFile::ParseFromFileWithOpts(const char* FileName, int RequireNullTerminated)
{
    /*if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        sprintf_s(LogBufB, "JsonFile::ParseFromFile <- char* FileName=%s, int RequireNullTerminated=%d", FileName, RequireNullTerminated); GlobalLogB.AddLog(LogBufB);
    }*/
    Clear();

    ExtFileClass Fp;
    if (!Fp.Open(FileName, "r"))return;
    Fp.Seek(0, SEEK_END);
    int Pos = Fp.Position();
    char* FileStr;
    FileStr = new char[Pos + 50];
    if (FileStr == nullptr)return;
    Fp.Seek(0, SEEK_SET);
    Fp.Read(FileStr, 1, Pos);
    FileStr[Pos] = 0;
    Fp.Close();

    int iPos = 0;
    while (FileStr[iPos] != '{' && iPos < Pos)iPos++;
    if (iPos == Pos) { delete[]FileStr; return; }

    const char* ReturnParseEnd;
    cJSON_Minify(FileStr + iPos);
    File = cJSON_ParseWithOpts(FileStr + iPos, &ReturnParseEnd, RequireNullTerminated);

    /*if (EnableLogEx)
    {
        GlobalLogB.AddLog_CurTime(false);
        GlobalLogB.AddLog("JsonFile::ParseFromFileWithOpts �� JSON�ı���");
        GlobalLogB.AddLog_CurTime(false);
        GlobalLogB.AddLog("\"", false);
        GlobalLogB.AddLog(UTF8toANSI(FileStr + iPos).c_str(), false);
        GlobalLogB.AddLog("\"");
    }*/

    delete[]FileStr;
}
#endif

const char* const StrBool_TrueList[]
{
    "true","True","TRUE",
    "yes","Yes","YES",
    "t","T","y","Y","1"
};
const char* const StrBool_FalseList[]
{
    "false","False","FALSE",
    "no","No","NO",
    "f","F","n","N","0"
};

std::string StrBoolImpl(bool Val, StrBoolType Type)
{
    return std::string{ CStrBoolImpl(Val, Type) };
}
const char* CStrBoolImpl(bool Val, StrBoolType Type)
{
    return (Val ? StrBool_TrueList : StrBool_FalseList)[(size_t)Type];
}

JsonObject JsonObject::CreateObjectItem(const std::string& Str) const
{
    auto ObjPtr = cJSON_CreateNull();
    cJSON_AddItemToObject(Object, Str.c_str(), ObjPtr);
    return JsonObject(ObjPtr);
}
void JsonObject::AddObjectItem(const std::string& Str, JsonObject Child, bool NeedsCopy) const
{
    cJSON_AddItemToObject(Object, Str.c_str(), (NeedsCopy ? cJSON_Duplicate(Child.GetRaw(), true) : Child.GetRaw()));
}
void JsonObject::AddNull(const std::string& Str) const
{
    cJSON_AddNullToObject(Object, Str.c_str());
}
void JsonObject::AddInt(const std::string& Str, int Val) const
{
    cJSON_AddIntegerToObject(Object, Str.c_str(), Val);
}
void JsonObject::AddDouble(const std::string& Str, double Val) const
{
    cJSON_AddNumberToObject(Object, Str.c_str(), Val);
}
void JsonObject::AddString(const std::string& Str, const std::string& Val) const
{
    cJSON_AddStringToObject(Object, Str.c_str(), Val.c_str());
}
void JsonObject::AddBool(const std::string& Str, bool Val) const
{
    cJSON_AddBoolToObject(Object, Str.c_str(), Val);
}
void JsonObject::AddStrBool(const std::string& Str, bool Val, StrBoolType Type) const
{
    cJSON_AddStringToObject(Object, Str.c_str(), CStrBoolImpl(Val, Type));
}
JsonFile JsonObject::SwapNull() const
{
    JsonFile F(cJSON_CreateNull());
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::SwapInt(int Val) const
{
    JsonFile F(JsonObject(cJSON_CreateInteger(Val)));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::SwapDouble(double Val) const
{
    JsonFile F(JsonObject(cJSON_CreateNumber(Val)));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::SwapString(const std::string& Val) const
{
    JsonFile F(JsonObject(cJSON_CreateString(Val.c_str())));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::SwapBool(bool Val) const
{
    JsonFile F(JsonObject(cJSON_CreateBool(Val)));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::SwapStrBool(bool Val, StrBoolType Type) const
{
    JsonFile F(JsonObject(cJSON_CreateString(CStrBoolImpl(Val, Type))));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::CopyAndSwap(JsonObject Obj, bool Recurse) const
{
    JsonFile F(JsonObject(cJSON_Duplicate(Obj.GetRaw(), Recurse)));
    cJson_SwapData(F.GetRaw(), Object);
    return F;
}
JsonFile JsonObject::RedirectAndSwap(JsonObject Obj)
{
    JsonFile F(*this);
    Object = Obj.GetRaw();
    return F;
}
void JsonObject::SwapObject(JsonObject Obj) const 
    { cJson_SwapData(Obj.GetRaw(), Object); }
void JsonObject::SetNull() const
    { SwapNull(); }
void JsonObject::SetInt(int Val) const 
    { SwapInt(Val); }
void JsonObject::SetDouble(double Val) const 
    { SwapDouble(Val); }
void JsonObject::SetString(const std::string& Val) const 
    { SwapString(Val); }
void JsonObject::SetBool(bool Val) const 
    { SwapBool(Val); }
void JsonObject::SetStrBool(bool Val, StrBoolType Type) const 
    { SwapStrBool(Val, Type); }
void JsonObject::CopyObject(JsonObject Obj, bool Recurse) const 
    { CopyAndSwap(Obj, Recurse); }
void JsonObject::RedirectObject(JsonObject Obj) 
    { RedirectAndSwap(Obj); }