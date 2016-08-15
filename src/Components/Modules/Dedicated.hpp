namespace Components
{
	class Dedicated : public Component
	{
	public:
		typedef void(Callback)();

		Dedicated();
		~Dedicated();

#ifdef DEBUG
		const char* GetName() { return "Dedicated"; };
#endif

		static bool IsEnabled();

		static void Heartbeat();

		static void OnFrame(Callback* callback);
		static void Once(Callback* callback);

	private:
		static wink::signal<wink::slot<Callback>> FrameSignal;
		static wink::signal<wink::slot<Callback>> FrameOnceSignal;

		static bool SendChat;

		static void MapRotate();
		static void FrameStub();
		static void InitDedicatedServer();

		static void PostInitialization();
		static void PostInitializationStub();

		static const char* EvaluateSay(char* text);

		static void PreSayStub();
		static void PostSayStub();
	};
}
