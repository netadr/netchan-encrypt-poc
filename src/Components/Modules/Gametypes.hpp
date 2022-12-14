#pragma once

namespace Components
{
	class Gametypes : public Component
	{
	public:
		Gametypes();

	private:
		static unsigned int GetGametypeCount();
		static const char* GetGametypeText(unsigned int index, int column);
		static void SelectGametype(unsigned int index);

		static void* BuildGametypeList(const char* file, void* buffer, size_t size);
	};
}
