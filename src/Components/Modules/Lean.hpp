#pragma once

#define BUTTON_FLAG_LEANLEFT 0x40
#define BUTTON_FLAG_LEANRIGHT 0x80

namespace Components
{
	class Lean : public Component
	{
	public:
		Lean();

	private:
		static Game::kbutton_t in_leanleft;
		static Game::kbutton_t in_leanright;

		static void IN_LeanLeft_Up();
		static void IN_LeanLeft_Down();

		static void IN_LeanRight_Up();
		static void IN_LeanRight_Down();

		static void CL_CmdButtonsStub();
		static void SetLeanFlags(Game::usercmd_s* cmds);
	};
}
