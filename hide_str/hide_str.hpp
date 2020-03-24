#ifndef HIDE_STR_HPP
#define HIDE_STR_HPP

#include <array>
#include <random>

using namespace std;

namespace hide_string
{
	#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
	#define hide_str(s) (hide_string_impl<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())

	class xtea3
	{
	public:
		xtea3();

		virtual ~xtea3();

	private:
		static uint32_t const block_size = 16;
		static uint32_t const xtea3_delta = 0x9E3889B9;

		uint8_t* data_ptr_ = nullptr;
		uint32_t size_crypt_ = 0;
		uint32_t size_decrypt_data_ = 0;
	protected:
		static uint32_t rol(const uint32_t base, uint32_t shift)
		{
			shift &= 0x1F;
			const int32_t res = base << shift | base >> unsigned(32 - shift);
			return res;
		};

		static void xtea3_encipher(const int32_t num_rounds, uint32_t* v, const uint32_t* k)
		{
			const int32_t delta = xtea3_delta;
			int32_t sum = 0;
			int32_t a = v[0] + k[0];
			int32_t b = v[1] + k[1];
			int32_t c = v[2] + k[2];
			int32_t d = v[3] + k[3];
			for (int32_t i = 0; i < num_rounds; i++)
			{
				a += (b << 4) + rol(k[sum % 4 + 4], b) ^ d + sum ^ (b >> 5) + rol(k[sum % 4], b >> 27);
				sum += delta;
				c += (d << 4) + rol(k[(sum >> 11) % 4 + 4], d) ^ b + sum ^ (d >> 5) + rol(k[(sum >> 11) % 4], d >> 27);
				const int32_t t = a;
				a = b;
				b = c;
				c = d;
				d = t;
			}
			v[0] = a ^ k[4];
			v[1] = b ^ k[5];
			v[2] = c ^ k[6];
			v[3] = d ^ k[7];
		};

		static void xtea3_decipher(const int32_t num_rounds, uint32_t* v, const uint32_t* k)
		{
			const int32_t delta = xtea3_delta;
			int32_t sum = delta * num_rounds;
			int32_t d = v[3] ^ k[7];
			int32_t c = v[2] ^ k[6];
			int32_t b = v[1] ^ k[5];
			int32_t a = v[0] ^ k[4];
			for (int32_t i = 0; i < num_rounds; i++)
			{
				const int32_t t = d;
				d = c;
				c = b;
				b = a;
				a = t;
				c -= (d << 4) + rol(k[(sum >> 11) % 4 + 4], d) ^ b + sum ^ (d >> 5) + rol(k[(sum >> 11) % 4], d >> 27);
				sum -= delta;
				a -= (b << 4) + rol(k[sum % 4 + 4], b) ^ d + sum ^ (b >> 5) + rol(k[sum % 4], b >> 27);
			}
			v[3] = d - k[3];
			v[2] = c - k[2];
			v[1] = b - k[1];
			v[0] = a - k[0];
		};

		static void xtea3_data_crypt(uint8_t* inout, const uint32_t len, const bool encrypt, const uint32_t* key)
		{
			static unsigned char data_array[block_size];
			for (int32_t i = 0; i < static_cast<int32_t>(len / block_size); i++)
			{
				memcpy(data_array, inout, block_size);
				if (encrypt)
				{
					xtea3_encipher(48, reinterpret_cast<uint32_t*>(data_array), key);
				}
				else
				{
					xtea3_decipher(48, reinterpret_cast<uint32_t*>(data_array), key);
				}
				memcpy(inout, data_array, block_size);
				inout = inout + block_size;
			}
			if (len % block_size != 0)
			{
				const int32_t mod = len % block_size;
				const int32_t offset = len / block_size * block_size;
				uint32_t data[block_size];
				memcpy(data, inout + offset, mod);
				if (encrypt)
				{
					xtea3_encipher(32, static_cast<uint32_t*>(data), key);
				}
				else
				{
					xtea3_decipher(32, static_cast<uint32_t*>(data), key);
				}
				memcpy(inout + offset, data, mod);
			}
		}

		uint8_t* data_crypt(const uint8_t* data, const uint32_t key[8], const uint32_t size)
		{
			int32_t size_crypt_tmp = size;

			while (size_crypt_tmp % 16 != 0)
			{
				size_crypt_tmp++;
			}

			data_ptr_ = nullptr;
			data_ptr_ = static_cast<uint8_t*>(malloc(size_crypt_tmp + 8));
			if (data_ptr_ == nullptr)
			{
				return nullptr;
			}

			size_crypt_ = size_crypt_tmp + 8;
			size_decrypt_data_ = size;
			memcpy(data_ptr_, reinterpret_cast<char*>(&size_crypt_), 4);
			memcpy(data_ptr_ + 4, reinterpret_cast<char*>(&size_decrypt_data_), 4);
			memcpy(data_ptr_ + 8, data, size);

			xtea3_data_crypt(data_ptr_ + 8, size_crypt_ - 8, true, key);
			return data_ptr_;
		}

		uint8_t* data_decrypt(const uint8_t* data, const uint32_t key[8], const uint32_t size)
		{
			memcpy(reinterpret_cast<char*>(&size_crypt_), data, 4);
			memcpy(reinterpret_cast<char*>(&size_decrypt_data_), data + 4, 4);
			if (size_crypt_ <= size)
			{
				data_ptr_ = nullptr;
				data_ptr_ = static_cast<uint8_t*>(malloc(size_crypt_));
				if (data_ptr_ == nullptr)
				{
					return nullptr;
				}
				memcpy(data_ptr_, data + 8, size_crypt_ - 8);

				xtea3_data_crypt(data_ptr_, size_crypt_ - 8, false, key);
			}
			else
			{
				return nullptr;
			}
			return data_ptr_;
		}

		uint32_t get_crypt_size() const
		{
			return size_crypt_;
		}
	};

	inline xtea3::xtea3() = default;

	inline xtea3::~xtea3() = default;

	inline uint32_t murmur3(const void* key, int32_t len, const int32_t seed)
	{
		const int32_t m = 0x5bd1e995;
		int32_t l = len;
		const int r = 24;
		const auto* data = static_cast<const unsigned char*>(key);
		int32_t h = seed;
		while (len >= 4)
		{
			int32_t k = *(unsigned int*)data;
			mmix(h, k);
			data += 4;
			len -= 4;
		}
		int32_t t = 0;
		switch (len)
		{
		case 3: t ^= data[2] << 16;
		case 2: t ^= data[1] << 8;
		case 1: t ^= data[0];
		default: ;
		}
		mmix(h, t);
		mmix(h, l);
		h ^= h >> 13;
		h *= m;
		h ^= h >> 15;
		return h;
	}

	constexpr const char* time = __TIME__;

	constexpr int seed = static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10 + static_cast<int>(time[4]) * 60 +
		static_cast<int>(time[3]) * 600 + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

	template <int32_t N>
	struct random_generator_string
	{
	private:
		static constexpr int32_t a = 16807;
		static constexpr int32_t m = 2147483647;
		static constexpr int32_t s = random_generator_string<N - 1>::value;
		static constexpr int32_t lo = a * (s & 0xFFFF);
		static constexpr int32_t hi = a * (s >> 16);
		static constexpr int32_t lo2 = lo + ((hi & 0x7FFF) << 16);
		static constexpr int32_t hi2 = hi >> 16;
		static constexpr int32_t lo3 = lo2 + hi;

	public:
		static constexpr int32_t max = m;
		static constexpr int32_t value = lo3 > m ? lo3 - m : lo3;
	};

	template <>
	struct random_generator_string<0>
	{
		static constexpr int32_t value = seed;
	};

	template <int32_t N, int32_t M>
	struct random_int
	{
		static constexpr int value = random_generator_string<N + 1>::value % M;
	};

	template <int32_t N>
	struct random_char
	{
		static const char value = static_cast<char>(1 + random_int<N, 0x7F - 1>::value);
	};

	template <size_t N, int K>
	class hide_string_impl final : protected xtea3
	{
		const char key_;
		uint32_t key_for_xtea3_[8]{};
		uint8_t* crypted_str_;
		array<char, N + 1> encrypted_;

		constexpr char enc(const char c) const
		{
			return c ^ key_;
		}

		char dec(const char c) const
		{
			return c ^ key_;
		}

	public:
		template <size_t... Is>
		constexpr hide_string_impl(const char* str, index_sequence<Is...>)
			: key_(random_char<K>::value), encrypted_
			  {
				  enc(str[Is])...
			  }
		{
			uint32_t value_for_gen_key = seed;

			for (uint32_t i = 0; i < 8; i++)
			{
				key_for_xtea3_[i] = murmur3(&value_for_gen_key, sizeof value_for_gen_key, i);
			}

			crypted_str_ = data_crypt(reinterpret_cast<const uint8_t*>(encrypted_.data()), key_for_xtea3_, N);
		}

		uint8_t* decrypt()
		{
			uint32_t value_for_gen_key = seed;

			for (uint32_t i = 0; i < 8; i++)
			{
				key_for_xtea3_[i] = murmur3(&value_for_gen_key, sizeof value_for_gen_key, i);
			}

			uint8_t* decrypted_str = data_decrypt(crypted_str_, key_for_xtea3_, this->get_crypt_size());

			if (decrypted_str == nullptr)
			{
				return nullptr;
			}

			for (size_t i = 0; i < N; ++i)
			{
				decrypted_str[i] = dec(decrypted_str[i]);
			}

			decrypted_str[N] = '\0';

			return decrypted_str;
		}
	};
}
#endif
