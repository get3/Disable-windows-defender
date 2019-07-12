#pragma once

#include <string>

using namespace Microsoft::Win32;

namespace Disable_Windows_Defender
{
	class Program
	{
		static void Main();

	private:
		static void RegistryEdit(const std::wstring &regPath, const std::wstring &name, const std::wstring &value);

		static void CheckDefender();

		static void RunPS(const std::wstring &args);

	};
}
