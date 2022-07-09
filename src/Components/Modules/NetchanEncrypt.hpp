#pragma once

namespace Components
{
	class X25519 {
	public:
		enum class Type {
			TYPE_PUB,
			TYPE_SECRET
		};

		X25519()
		{
			crypto_kx_keypair(pk, sk);
		}

		X25519(const uint8_t* pub)
		{
			memcpy(pk, pub, sizeof(pk));
			sodium_memzero(sk, sizeof(sk));
		}

		X25519(const uint8_t* pub, const uint8_t* priv)
		{
			memcpy(pk, pub, sizeof(pk));
			memcpy(sk, priv, sizeof(sk));
		}

		~X25519()
		{
			sodium_memzero(pk, sizeof(pk));
			sodium_memzero(sk, sizeof(sk));
		}

		const std::span<const uint8_t> GetKey(Type type) const
		{
			switch (type)
			{
			case Type::TYPE_PUB:
				return pk;
				break;
			case Type::TYPE_SECRET:
				return sk;
				break;
			default:
				return pk;
				break;
			}
		}
	private:
		uint8_t pk[crypto_kx_PUBLICKEYBYTES];
		uint8_t sk[crypto_kx_SECRETKEYBYTES];
	};

	class Signature {
	public:
		Signature()
		{
			sodium_memzero(pk, sizeof(pk));
		}

		Signature(const uint8_t* pub)
		{
			memcpy(pk, pub, sizeof(pk));
		}

		~Signature()
		{
			sodium_memzero(pk, sizeof(pk));
		}

		bool Verify(const std::span<const uint8_t> message, const uint8_t* sig) const
		{
			return (crypto_sign_verify_detached(sig, message.data(), message.size(), pk) == 0);
		}
	private:
		uint8_t pk[crypto_sign_PUBLICKEYBYTES];
	};

	class SecureChannel {
	public:
		enum class Mode {
			MODE_CLIENT,
			MODE_SERVER
		};

		static constexpr size_t AD_CLIENT_LEN = 4; // Size of sequence number
		static constexpr size_t AD_SERVER_LEN = 6; // Size of sequence number + qport
		static constexpr size_t COMBINED_LEN = crypto_aead_xchacha20poly1305_IETF_ABYTES + crypto_aead_xchacha20poly1305_IETF_NPUBBYTES; // Size of crypto data appended to packet

		SecureChannel(Mode mode_) : mode(mode_)
		{
			rx_adlen = mode_ == Mode::MODE_CLIENT ? AD_CLIENT_LEN : AD_SERVER_LEN;
			tx_adlen = mode_ == Mode::MODE_CLIENT ? AD_SERVER_LEN : AD_CLIENT_LEN;
			Reset();
		}

		SecureChannel(SecureChannel&& source) noexcept : mode(source.mode)
		{
			rx_adlen = source.rx_adlen;
			tx_adlen = source.tx_adlen;
			memcpy(rx_key, source.rx_key, sizeof(rx_key));
			memcpy(tx_key, source.tx_key, sizeof(tx_key));
			source.Reset();
		}

		~SecureChannel()
		{
			Reset();
		}

		bool Setup(const uint8_t* a_pk, const uint8_t* a_sk, const uint8_t* b_pk)
		{
			int result = 1;

			switch (mode)
			{
			case Mode::MODE_CLIENT:
				result = crypto_kx_client_session_keys(rx_key, tx_key, a_pk, a_sk, b_pk);
				break;
			case Mode::MODE_SERVER:
				result = crypto_kx_server_session_keys(rx_key, tx_key, a_pk, a_sk, b_pk);
				break;
			}

			return result == 0;
		}

		void Reset()
		{
			sodium_memzero(rx_key, sizeof(rx_key));
			sodium_memzero(tx_key, sizeof(tx_key));
		}

		bool Decrypt(Game::msg_t* msg) const
		{
			int result = 1;
			uint8_t* data = reinterpret_cast<uint8_t*>(msg->data);
			const int clen = msg->cursize - rx_adlen - COMBINED_LEN;

			if (clen > 0) // If this isn't true something has gone wrong (malformed packet)
			{
				const uint8_t* tag = &data[rx_adlen + clen];
				const uint8_t* nonce = &data[rx_adlen + clen + crypto_aead_xchacha20poly1305_IETF_ABYTES];

				result = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
					data + rx_adlen,
					nullptr,
					data + rx_adlen,
					clen,
					tag,
					data,
					rx_adlen,
					nonce,
					rx_key
				);

				msg->cursize = msg->cursize - COMBINED_LEN;
			}

			return result == 0;
		}

		bool Encrypt(Game::msg_t* msg) const
		{
			int result = 1;
			uint8_t* data = reinterpret_cast<uint8_t*>(msg->data);

			uint8_t tag[crypto_aead_xchacha20poly1305_IETF_ABYTES];
			uint8_t nonce[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES];

			randombytes_buf(nonce, sizeof(nonce));

			result = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
				data + tx_adlen,
				tag,
				nullptr,
				data + tx_adlen,
				msg->cursize - tx_adlen,
				data, // "associated data", i.e. the data that's not encrypted but still authenticated
				tx_adlen,
				nullptr,
				nonce,
				tx_key
			);

			Game::MSG_WriteData(msg, tag, sizeof(tag));
			Game::MSG_WriteData(msg, nonce, sizeof(nonce));

			assert(msg->overflowed == 0);

			return result == 0;
		}
	private:
		Mode mode;
		size_t rx_adlen;
		size_t tx_adlen;
		uint8_t rx_key[crypto_kx_SESSIONKEYBYTES];
		uint8_t tx_key[crypto_kx_SESSIONKEYBYTES];
	};

	class NetchanEncrypt : public Component {
	public:
		NetchanEncrypt();
		~NetchanEncrypt();
	private:
		static X25519 AsymmetricKey;
		static SecureChannel ClientChannel;
		static SecureChannel SavedServerChannel;
		static std::unordered_map<uint64_t, SecureChannel> ServerChannels;

		static void CheckForResendDataStub(Game::netsrc_t sock, Game::netadr_t adr, const char* format, int len);
		static void ConnectionlessPacketDirect(Game::netadr_t from, Game::msg_t* msg);
		static void ConnectionlessPacketDirectStub();
		static void DirectConnectDataStub(Game::netsrc_t sock, Game::netadr_t adr, const char* data);
		static void ClientDeriveKey(int type, Game::msg_t* msg);
		static void ClientDeriveKeyStub();
		static bool ProcessClientStub(Game::netchan_t* chan, Game::msg_t* msg);
		static bool ProcessServerStub(Game::netchan_t* chan, Game::msg_t* msg);
		static bool Transmit(Game::netchan_t* chan, Game::msg_t* msg);
		static void TransmitStub();
		static void TransmitFragmentStub();
		static void ClearClientStateStub(int localClientNum);
		static void LiveRemoveClientStub(Game::client_t* cl, const char* reason, bool tellThem);

		static void OutboundPacketFilter(Game::netchan_t* chan, Game::msg_t* msg, SecureChannel::Mode mode);
		static Dvar::Var net_encrypt;
		static Dvar::Var net_filterMode;
		static Dvar::Var net_filterInterval;
	public:
		enum class FilterMode : std::int32_t
		{
			MODE_NONE = 0,
			MODE_SEQUENCE = 1,
			MODE_CIPHERTEXT = 2,
			MODE_TAG = 3,
			MODE_NONCE = 4,
			MODE_SHORTEN = 5
		};
	};
}