// Adapted from code provided for the assignment by prof. Ing. Pavol Zajac, PhD.
// Author: Michal Malik
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
//
#include "spn.hpp"

#include <iostream>


SPN::SPN() :
	m_SB{ std::vector<uint16_t>(16, 0) },
	m_iSB{ std::vector<uint16_t>(16, 0) },
	m_subkeys{ std::vector<uint16_t>(SPN::Nr + 1, 0) },
	m_diff_table{ 16, std::vector<uint16_t>(16) },
	m_transposed_diff_table{ 16, std::vector<uint16_t>(16) }
{
}


bool SPN::keysched(const char* key)
{
	int i;
	//PRE: key = 80 bit hexstring -- 20 hex characters
	if (strlen(key) != 20)
		return false;

	for (i = 0; i <= Nr; i++)
	{
		if (sscanf(key + 4 * i, "%04hx", &m_subkeys[i]) != 1)
			return false;
	}

	return true;
}


void SPN::setSboxes(char* sbox)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		m_SB[i] = static_cast<uint16_t>(strtol(sbox, &sbox, 10));
	}

	for (i = 0; i < 16; i++)
	{
		m_iSB[m_SB[i]] = i;
	}
}


void SPN::calculateDiffTable()
{
	for (uint16_t x = 0; x <= 0xf; ++x)
	{
		uint16_t y = subst(x);

		for (uint16_t dx = 0; dx <= 0xf; ++dx)
		{
			uint16_t dy = y ^ subst(x ^ dx);
			m_diff_table[dx][dy] += 1;
			m_transposed_diff_table[dy][dx] += 1;
		}
	}
}


uint16_t SPN::subst(uint16_t x) const
{
	uint16_t y = 0;

	y = m_SB[x & 0xf];
	y ^= m_SB[(x >> 4) & 0xf] << 4;
	y ^= m_SB[(x >> 8) & 0xf] << 8;
	y ^= m_SB[(x >> 12) & 0xf] << 12;

	return y;
}


uint16_t SPN::isubst(uint16_t x) const
{
	uint16_t y = 0;

	y = m_iSB[x & 0xf];
	y ^= m_iSB[(x >> 4) & 0xf] << 4;
	y ^= m_iSB[(x >> 8) & 0xf] << 8;
	y ^= m_iSB[(x >> 12) & 0xf] << 12;

	return y;
}


uint16_t SPN::itransp(uint16_t x) const
{
	return transp(x);
}


uint16_t SPN::transp(uint16_t x) const
{
	uint16_t y = 0;

	y ^= ((x) & 0x8421);
	y ^= ((x) & 0x0842) << 3;
	y ^= ((x) & 0x0084) << 6;
	y ^= ((x) & 0x0008) << 9;
	y ^= ((x) & 0x1000) >> 9;
	y ^= ((x) & 0x2100) >> 6;
	y ^= ((x) & 0x4210) >> 3;

	return y;
}


uint16_t SPN::encrypt(uint16_t pt) const
{
	uint16_t x;
	int i;

	x = pt ^ m_subkeys[0];

	for (i = 1; i < Nr; i++)
	{
		x = subst(x);
		x = transp(x);
		x = x ^ m_subkeys[i];
	}

	x = subst(x);
	x = x ^ m_subkeys[Nr];

	return x;
}


uint16_t SPN::decrypt(uint16_t ct) const
{
	uint16_t x;
	int i;

	x = ct ^ m_subkeys[Nr];
	x = isubst(x);

	for (i = Nr - 1; i >= 1; i--)
	{
		x = x ^ m_subkeys[i];
		x = itransp(x);
		x = isubst(x);
	}

	x = x ^ m_subkeys[0];

	return x;
}


uint16_t SPN::decryptWithKeys(uint16_t ct, const std::vector<uint16_t>& subkeys) const
{
	uint16_t x;
	int i;

	x = ct ^ subkeys[Nr];
	x = isubst(x);

	for (i = Nr - 1; i >= 1; i--)
	{
		x = x ^ subkeys[i];
		x = itransp(x);
		x = isubst(x);
	}

	x = x ^ subkeys[0];

	return x;
}