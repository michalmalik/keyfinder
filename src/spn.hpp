// Adapted from code provided for the assignment by prof. Ing. Pavol Zajac, PhD.
// Author: Michal Malik
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
//
#pragma once

#include <cstdint>
#include <vector>


class SPN
{
public:
	explicit SPN();

	const std::vector<std::vector<uint16_t>>& getDiffTable() const { return m_diff_table; }
	const std::vector<std::vector<uint16_t>>& getTransposedDiffTable() const { return m_transposed_diff_table; }
	std::vector<uint16_t>& getSubkeys() { return m_subkeys; }

	bool keysched(const char* key);
	void setSboxes(char* sbox);
	void calculateDiffTable();

	uint16_t encrypt(uint16_t pt) const;
	uint16_t decrypt(uint16_t ct) const;
	// This function only exists for better parallelization
	uint16_t decryptWithKeys(uint16_t ct, const std::vector<uint16_t>& subkeys) const;
	uint16_t subst(uint16_t x) const;
	uint16_t isubst(uint16_t x) const;
	uint16_t itransp(uint16_t x) const;
	uint16_t transp(uint16_t x) const;

	static const size_t Nr = 4;

private:
	std::vector<uint16_t> m_SB;
	std::vector<uint16_t> m_iSB;
	std::vector<uint16_t> m_subkeys;
	std::vector<std::vector<uint16_t>> m_diff_table;
	std::vector<std::vector<uint16_t>> m_transposed_diff_table;
};