#include <STDInclude.hpp>

namespace Components
{
	X25519 NetchanEncrypt::AsymmetricKey;
	SecureChannel NetchanEncrypt::ClientChannel(SecureChannel::Mode::MODE_CLIENT);
	SecureChannel NetchanEncrypt::SavedServerChannel(SecureChannel::Mode::MODE_SERVER);
	std::unordered_map<uint64_t, SecureChannel> NetchanEncrypt::ServerChannels;
	Dvar::Var NetchanEncrypt::net_encrypt;
	Dvar::Var NetchanEncrypt::net_filterMode;
	Dvar::Var NetchanEncrypt::net_filterInterval;

	void NetchanEncrypt::CheckForResendDataStub(Game::netsrc_t sock, Game::netadr_t adr, const char* format, int len)
	{
		if (adr.type != Game::NA_LOOPBACK)
		{
			Proto::Crypt::Connect request;
			auto clientpubkey = AsymmetricKey.GetKey(X25519::Type::TYPE_PUB);
			request.set_clientpubkey(clientpubkey.data(), clientpubkey.size());

			Logger::Print("Connect request (SEND) - {}", request.DebugString());

			std::string bytes(format);
			bytes.push_back('\0'); // Ensure MSG_ReadStringLine in SV_ConnectionlessPacket stops at the correct place
			request.AppendToString(&bytes);

			return Game::NET_OutOfBandData(sock, adr, bytes.data(), bytes.size());
		}

		return Game::NET_OutOfBandData(sock, adr, format, len);
	}

	void NetchanEncrypt::ConnectionlessPacketDirect(Game::netadr_t from, Game::msg_t* msg)
	{
		if (from.type != Game::NA_LOOPBACK)
		{
			Proto::Crypt::Connect request;
			request.ParseFromArray(reinterpret_cast<void*>(&msg->data[msg->readcount]), msg->cursize - msg->readcount);

			Logger::Print("Connect request (RECV) - {}", request.DebugString());

			X25519 clientpubkey(reinterpret_cast<const uint8_t*>(request.clientpubkey().data()));

			if (!SavedServerChannel.Setup(AsymmetricKey.GetKey(X25519::Type::TYPE_PUB).data(),
				AsymmetricKey.GetKey(X25519::Type::TYPE_SECRET).data(), clientpubkey.GetKey(X25519::Type::TYPE_PUB).data()))
			{
				SavedServerChannel.Reset();
				return Game::NET_OutOfBandPrint(Game::NS_SERVER, from, "error\nThe server failed to set up session keys!");
			}
		}

		return Game::SV_DirectConnect(from);
	}

	__declspec(naked) void NetchanEncrypt::ConnectionlessPacketDirectStub()
	{
		__asm
		{
			mov edx, dword ptr[esp + 408h]
			mov ecx, dword ptr[esp + 40Ch] // We need an extra msg_t* parameter to our SV_DirectConnect stub 
			push esi                       // to be able to retrieve and parse the Connect protobuf message,
			sub esp, 14h                   // so I just lifted the param setup from SV_RecieveStats :shrug:
			mov eax, esp
			mov dword ptr[eax], edx
			mov edx, dword ptr[esp + 428h]
			mov dword ptr[eax + 4], ecx
			mov ecx, dword ptr[esp + 42Ch]
			mov dword ptr[eax + 8], edx
			mov edx, dword ptr[esp + 430h]
			mov dword ptr[eax + 0Ch], ecx
			mov dword ptr[eax + 10h], edx
			call NetchanEncrypt::ConnectionlessPacketDirect
			add esp, 18h
			push 626601h
			retn
		}
	}

	void NetchanEncrypt::DirectConnectDataStub(Game::netsrc_t sock, Game::netadr_t adr, const char* data)
	{
		if (adr.type != Game::NA_LOOPBACK)
		{
			ServerChannels.insert({
			static_cast<uint64_t>(adr.ip.full) << 16 | adr.port,
			std::move(SavedServerChannel)
				});

			Proto::Crypt::ConnectResponse response;
			auto serverpubkey = AsymmetricKey.GetKey(X25519::Type::TYPE_PUB);
			response.set_serverpubkey(serverpubkey.data(), serverpubkey.size());

			Logger::Print("Connect response (SEND) - {}", response.DebugString());

			std::string bytes("connectResponse");
			bytes.push_back('\0'); // Ensure MSG_ReadStringLine in CL_ConnectionlessPacket stops at the correct place
			response.AppendToString(&bytes);

			return Game::NET_OutOfBandData(sock, adr, bytes.data(), bytes.size());
		}

		return Game::NET_OutOfBandPrint(sock, adr, data);
	}

	void NetchanEncrypt::ClientDeriveKey(int type, Game::msg_t* msg)
	{
		if (type != Game::NA_LOOPBACK)
		{
			Proto::Crypt::ConnectResponse response;
			response.ParseFromArray(reinterpret_cast<void*>(&msg->data[msg->readcount]), msg->cursize - msg->readcount);

			Logger::Print("Connect response (RECV) - {}", response.DebugString());

			X25519 serverpubkey(reinterpret_cast<const uint8_t*>(response.serverpubkey().data()));

			if (!ClientChannel.Setup(AsymmetricKey.GetKey(X25519::Type::TYPE_PUB).data(),
				AsymmetricKey.GetKey(X25519::Type::TYPE_SECRET).data(), serverpubkey.GetKey(X25519::Type::TYPE_PUB).data()))
			{
				return Game::Com_Error(Game::ERR_DROP, "The client failed to set up session keys!");
			}
		}

		return;
	}

	__declspec(naked) void NetchanEncrypt::ClientDeriveKeyStub()
	{
		__asm
		{
			pushad
			mov eax, dword ptr[esp + 0CBCh]
			mov ecx, dword ptr[esp + 0CA8h]
			push eax
			push ecx
			call NetchanEncrypt::ClientDeriveKey
			add esp, 8
			popad
			mov edx, esi
			imul edx, 0AF4h
			push 5AA49Ah
			retn
		}
	}

	bool NetchanEncrypt::ProcessClientStub(Game::netchan_t* chan, Game::msg_t* msg)
	{
		if (chan->remoteAddress.type != Game::NA_LOOPBACK && net_encrypt.get<bool>())
		{
			if (!ClientChannel.Decrypt(msg))
			{
				Logger::Warning(Game::CON_CHANNEL_NETWORK, "Failed to authenticate message from {}.{}.{}.{}:{}, dropping...\n",
					chan->remoteAddress.ip.bytes[0], chan->remoteAddress.ip.bytes[1],
					chan->remoteAddress.ip.bytes[2], chan->remoteAddress.ip.bytes[3],
					chan->remoteAddress.port
				);
				return false;
			}
		}

		return Game::Netchan_Process(chan, msg);
	}

	bool NetchanEncrypt::ProcessServerStub(Game::netchan_t* chan, Game::msg_t* msg)
	{
		if (chan->remoteAddress.type != Game::NA_LOOPBACK && net_encrypt.get<bool>())
		{
			uint64_t key = static_cast<uint64_t>(chan->remoteAddress.ip.full) << 16 | chan->remoteAddress.port;
			if (!ServerChannels.at(key).Decrypt(msg))
			{
				Logger::Warning(Game::CON_CHANNEL_NETWORK, "Failed to authenticate message from {}.{}.{}.{}:{}, dropping...\n",
					chan->remoteAddress.ip.bytes[0], chan->remoteAddress.ip.bytes[1],
					chan->remoteAddress.ip.bytes[2], chan->remoteAddress.ip.bytes[3],
					chan->remoteAddress.port
				);
				return false;
			}
		}

		return Game::Netchan_Process(chan, msg);
	}

	bool NetchanEncrypt::Transmit(Game::netchan_t* chan, Game::msg_t* msg)
	{
		if (chan->remoteAddress.type != Game::NA_LOOPBACK && net_encrypt.get<bool>())
		{
			if (Game::IsServerRunning())
			{
				uint64_t key = static_cast<uint64_t>(chan->remoteAddress.ip.full) << 16 | chan->remoteAddress.port;
				ServerChannels.at(key).Encrypt(msg);
#ifdef DEBUG
				OutboundPacketFilter(chan, msg, SecureChannel::Mode::MODE_SERVER);
#endif
			}
			else
			{
				ClientChannel.Encrypt(msg);
#ifdef DEBUG
				OutboundPacketFilter(chan, msg, SecureChannel::Mode::MODE_CLIENT);
#endif
			}
		}

		return true;
	}

	__declspec(naked) void NetchanEncrypt::TransmitStub()
	{
		__asm
		{
			pushad
			mov eax, esp
			add eax, 28h
			push eax
			push esi
			call NetchanEncrypt::Transmit
			add esp, 8
			popad
			mov edx, [esi + 10h]
			mov ecx, [esi + 14h]
			push 46BB2Bh
			retn
		}
	}

	__declspec(naked) void NetchanEncrypt::TransmitFragmentStub()
	{
		__asm
		{
			pushad
			mov eax, esp
			add eax, 54h
			push eax
			push esi
			call NetchanEncrypt::Transmit
			add esp, 8
			popad
			mov edx, [esi + 10h]
			mov ecx, [esi + 14h]
			push 47C171h
			retn
		}
	}

	void NetchanEncrypt::ClearClientStateStub(int localClientNum)
	{
		ClientChannel.Reset();
		return Game::CL_ClearClientState(localClientNum);
	}

	void NetchanEncrypt::LiveRemoveClientStub(Game::client_t* cl, const char* reason, bool tellThem)
	{
		uint64_t key = static_cast<uint64_t>(cl->netchan.remoteAddress.ip.full) << 16 | cl->netchan.remoteAddress.port;
		ServerChannels.erase(key);

		return Game::SV_Live_RemoveClient(cl, reason, tellThem);
	}

	void NetchanEncrypt::OutboundPacketFilter(Game::netchan_t* chan, Game::msg_t* msg, SecureChannel::Mode mode) // Simulate tampering with various parts of the packet data
	{
		bool modify = (chan->outgoingSequence % net_filterInterval.get<int>() == 0);
		size_t adlen = SecureChannel::AD_CLIENT_LEN;

		if (mode == SecureChannel::Mode::MODE_CLIENT)
			adlen = SecureChannel::AD_SERVER_LEN;

		if (modify && msg->cursize - adlen - SecureChannel::COMBINED_LEN > 0)
		{
			switch (static_cast<FilterMode>(net_filterMode.get<int>()))
			{
			case FilterMode::MODE_SEQUENCE:
				*(msg->data) = static_cast<char>(rand());
				break;
			case FilterMode::MODE_CIPHERTEXT:
				msg->data[adlen] = static_cast<char>(rand());
				break;
			case FilterMode::MODE_TAG:
				msg->data[adlen + (msg->cursize - adlen - SecureChannel::COMBINED_LEN)] = static_cast<char>(rand());
				break;
			case FilterMode::MODE_NONCE:
				msg->data[adlen + (msg->cursize - adlen - SecureChannel::COMBINED_LEN) + crypto_aead_xchacha20poly1305_IETF_ABYTES] = static_cast<char>(rand());
				break;
			case FilterMode::MODE_SHORTEN:
				msg->cursize = msg->cursize - SecureChannel::COMBINED_LEN;
				break;
			default:
				break;
			}
		}

	}

	NetchanEncrypt::NetchanEncrypt()
	{
		Scheduler::Once([] {
			sodium_init();
			AsymmetricKey = X25519(); // Regenerating the key pair here since we've called sodium_init

			net_encrypt = Game::Dvar_RegisterBool("net_encrypt", true, Game::DVAR_LATCH, "Encrypt and authenticate network packets from peers.");

#ifdef DEBUG
			static const char* values[] = {
				"None",
				"Sequence",
				"Ciphertext",
				"Tag",
				"Nonce",
				"Shorten",
				nullptr
			};

			net_filterMode = Game::Dvar_RegisterEnum("net_filterMode", values, 0, Game::DVAR_NONE, "Filter and modify outbound packets to test authentication.");
			net_filterInterval = Game::Dvar_RegisterInt("net_filterInterval", 20, 20, std::numeric_limits<int>::max(), Game::DVAR_NONE, "How often (in number of packets) outbound packets should be modified.");
#endif
			}, Scheduler::Pipeline::MAIN);



		Utils::Hook(0x41D3E3, NetchanEncrypt::CheckForResendDataStub, HOOK_CALL).install()->quick(); // CL_CheckForResend
		Utils::Hook(0x6265C3, NetchanEncrypt::ConnectionlessPacketDirectStub, HOOK_JUMP).install()->quick(); // SV_ConnectionlessPacket
		Utils::Hook(0x461305, NetchanEncrypt::DirectConnectDataStub, HOOK_CALL).install()->quick(); // SV_DirectConnect
		Utils::Hook(0x5AA492, NetchanEncrypt::ClientDeriveKeyStub, HOOK_JUMP).install()->quick(); // CL_DispatchConnectionlessPacket
		Utils::Hook(0x45D08D, NetchanEncrypt::ProcessClientStub, HOOK_CALL).install()->quick(); // CL_PacketEvent
		Utils::Hook(0x6268D4, NetchanEncrypt::ProcessServerStub, HOOK_CALL).install()->quick(); // SV_PacketEvent
		Utils::Hook(0x46BB25, NetchanEncrypt::TransmitStub, HOOK_JUMP).install()->quick(); // Netchan_Transmit
		Utils::Hook(0x47C16B, NetchanEncrypt::TransmitFragmentStub, HOOK_JUMP).install()->quick(); // Netchan_TransmitNextFragment
		Utils::Hook(0x403637, NetchanEncrypt::ClearClientStateStub, HOOK_CALL).install()->quick(); // CL_Disconnect
		Utils::Hook(0x4F6F56, NetchanEncrypt::LiveRemoveClientStub, HOOK_CALL).install()->quick(); // SV_CheckTimeouts
	}

	NetchanEncrypt::~NetchanEncrypt()
	{
	}
}