#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"
#include "Setting.h"
#include <string>

#include <commctrl.h>

int Run(std::string_view const arguments) {

	InitCommonControls();

	Log::Open("syringe.log");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	ReadSetting();
	Log::WriteLine();
	Log::WriteLine("WinMain: �����в����� \"%.*s\"", printable(arguments));

	auto failure = "��ִ���ļ�����ʧ�ܣ�";
	auto exit_code = ERROR_ERRORS_ENCOUNTERED;

	try
	{
		auto const command = get_command_line(arguments);
		Log::WriteLine("WinMain: ��ִ���ļ�Ϊ�� \"%.*s\"", printable(command.executable));
		Log::WriteLine("WinMain: ��������Ϊ�� \"%.*s\"", printable(command.arguments));

		if(!command.flags.empty()) {
			// artificial limitation
			throw invalid_command_arguments{};
		}

		Log::WriteLine(
			"WinMain: ��ʼ�����ִ���ļ��� \"%.*s\"����",
			printable(command.executable));
		Log::WriteLine();

		SyringeDebugger Debugger{ command.executable };
		failure = "�޷����п�ִ���ļ���";

		Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
		Log::WriteLine();
		SetEnvironmentVariable("HERE_IS_SYRINGE", "1");
		Debugger.FindDLLs();
		SetEnvironmentVariable("HERE_IS_SYRINGE", NULL);

		Log::WriteLine(
			"WinMain: SyringeDebugger::Run(\"%.*s\");",
			printable(command.arguments));
		Log::WriteLine();

		Debugger.Run(command.arguments);
		Log::WriteLine("WinMain: SyringeDebugger::Run ������С�");
		Log::WriteLine("WinMain: ��������������");
		return ERROR_SUCCESS;
	}
	catch(lasterror const& e)
	{
		auto const message = replace(e.message, "%1", e.insert);
		Log::WriteLine("WinMain: %s (%d)", message.c_str(), e.error);

		auto const msg = std::string(failure) + "\n\n" + message;
		MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

		exit_code = static_cast<long>(e.error);
	}
	catch(invalid_command_arguments const&)
	{
		MessageBoxA(
			nullptr, "Syringe ����ֱ������.\n\n"
			"ʹ�÷���:\n��Syringe.json������DefaultExecutableNameΪ����ֵ\n��ͨ�������л�BAT�ļ���\nSyringe.exe \"<exe name>\" <arguments>",
			VersionString, MB_OK | MB_ICONINFORMATION);

		Log::WriteLine(
			"WinMain: ��������ȱ�ٻ���������˳�����");

		exit_code = ERROR_INVALID_PARAMETER;
	}

	Log::WriteLine("WinMain: �����쳣������");
	return static_cast<int>(exit_code);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	return Run(lpCmdLine);
}
