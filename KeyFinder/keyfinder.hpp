// keyfinder.hpp
// Author: Michal Malik
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
// Last subkey recovery algorithm by http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf
//
#pragma once

#include <vector>
#include <set>
#include <map>
#include <bitset>

#include "spn.hpp"


class KeyFinder
{
public:
	struct HistReturn
	{
		uint16_t key;
		size_t value;
		HistReturn(uint16_t _key, size_t _value) : key{ _key }, value{ _value } {}
	};

	struct Path
	{
		uint16_t input_diff;
		uint16_t output_diff;
		double probability;
		Path(uint16_t _id, uint16_t _od, double _p) : input_diff{ _id }, output_diff{ _od }, probability{ _p } {}
	};

	struct SboxState
	{
		std::bitset<4> active;
		uint16_t mask;
		std::set<uint16_t> aux_masks;
		SboxState(uint16_t state) : active{ state }, mask{ 0 }, aux_masks{}
		{
			for (int i = (int)active.size() - 1; i >= 0; i--)
			{
				if (active[i])
				{
					mask |= (0x000f << i * 4);
					aux_masks.insert((0x000f << i * 4));
				}
			}
		}
	};

	enum VerboseLevel : int
	{
		VERBOSE_NONE = 0,
		VERBOSE_INFO,
		VERBOSE_MEDIUM,
		VERBOSE_VERY
	};

	explicit KeyFinder(
		const std::string& ct_file,
		SPN& spn,
		size_t num_of_threads = DEFAULT_NUM_OF_THREADS,
		bool compute_3_sboxes = false,
		bool compute_4_sboxes = false);

	std::vector<uint16_t> &getSubkeys() { return m_subkeys; }
	const std::vector<std::vector<uint16_t>>& getDiffTable() const { return m_spn.getDiffTable(); }
	void setVerbose(int level) { m_verbose = static_cast<VerboseLevel>(level); }
	std::string getKeyStr() const;

	bool testKey(const std::string& key) const;

	// Subkey recovery functions
	//
	// recoverFirstSubkey - uses recoverRoundSubkey(0)
	// recoverLastSubkey - uses recoverRoundSubkey(4)
	// recoverSecondSubkey
	//		- this is only ever used if the other subkeys are calculated
	//		(not checked in the function though)
	//		- exits with 0xbabebabe if no key found as this should never happen
	// 
	// recoverRoundSubkey - "main worker" function that recovers a subkey nibble after nibble combining
	//		histograms from multiple best paths
	uint16_t recoverFirstSubkey();
	uint16_t recoverSecondSubkey() const;
	uint16_t recoverRoundSubkey(size_t round_num) const;
	uint16_t recoverLastSubkey();
	
	// Helper functions
	//
	// 0 means leftmost sbox, 3 rightmost; does NOT take invalid values into account!
	//
	// MakeSbox(1, 0x5) = 0x0500
	// MakeSbox(3, 0xf) = 0x000f
	static constexpr uint16_t MakeSbox(size_t which, uint16_t x) { return (x & 0xf) << (3 - which) * 4; }

	// SboxMask(1) = 0x0f00
	// SboxMask(3) = 0x00f0
	static constexpr uint16_t SboxMask(size_t which) { return (0x000f) << (3 - which) * 4; }
	
	// Return value of a given sbox
	// SboxValue(0, 0x5000) = 0x5
	static constexpr uint16_t SboxValue(size_t which, uint16_t x) { return (x >> (3 - which) * 4) & 0xf; }

	// Return a vector of set sboxes for a given value
	// FindSbox(0x5050) = {0, 2}
	// FindSbox(0x0505) = {1, 3}
	static std::vector<uint16_t> FindSbox(uint16_t x)
	{
		std::vector<uint16_t> set_sboxes;
		for (uint16_t i = 0; i < 4; ++i)
		{
			if ((x & (0x000f << (3 - i) * 4)) != 0)
			{
				set_sboxes.push_back(i);
			}
		}
		return set_sboxes;
	}

	// Return count of activated sboxes
	// 0xf000 => 1
	// 0xf0f0 => 2
	static size_t SboxCount(uint16_t x)
	{
		size_t count = 0;
		for (uint16_t i = 0; i <= 0xf; i += 4)
		{
			if ((x & (0x000f << i)) != 0)
			{
				++count;
			}
		}
		return count;
	}

	// 0x1010 => 0xf0f0
	static uint16_t Mask(uint16_t x)
	{
		uint16_t mask = 0;
		for (uint16_t i = 0; i <= 0xf; i += 4)
		{
			if ((x & (0x000f << i)) != 0)
			{
				mask |= (0x000f << i);
			}
		}
		return mask;
	}

	static const size_t DEFAULT_NUM_OF_THREADS{ 1 };

private:
	SPN& m_spn;
	std::vector<uint16_t> m_pc1;
	std::vector<uint16_t> m_pc1_forward;
	std::vector<uint16_t> m_subkeys;
	VerboseLevel m_verbose{ VERBOSE_NONE };
	bool m_compute_3_sboxes{ false };
	bool m_compute_4_sboxes{ false };
	size_t m_num_of_threads{ DEFAULT_NUM_OF_THREADS };

	// This is a bit of a "magic function", so bear with me
	//
	// The input is sbox_state_to_key_hist, which basically looks like this:
	//
	// ...
	// 0b1000: { 0xf000: 2, 0xa000: 5, 0xb000: 6, ...  }
	// 0b1001: { 0xf005: 10, 0xa001: 4, 0xb00f: 5, ... }
	// ...
	//
	// For sbox with index 0 active (leftmost), we consider the key 0b1000 its "main" -- this tells us how many times a certain key occured when
	// we generated a path in a certain round with only sbox 0 active.
	//
	// Then, we take every sbox that has sbox 0 active too, so in this case they would be these:
	//		0b1001
	//		0b1100
	//		0b1010
	//		0b1110 -- depends on compute_3_sboxes
	//		0b1011 -- depends on compute_3_sboxes
	//		0b1111 -- depends on compute_4_sboxes
	//
	// We go over their occurences and mask their keys with the mask for sbox 0, which is 0xf000 and add the number of occurences into "main" using the masked key.
	// So for example, if we went over occurences for 0b1001, its values look like 0xf005, 0xa001 etc.
	// We would go over them and do the following:
	//
	//		main[key & MaskForSbox(0)]
	//		main[0xf005 & 0xf000] => mask[0xf000] += occurences
	// 
	// So after we did this, our "main" (for the example above would look like so):
	//
	// 0b1000: { 0xf000: 12, 0xa000: 9, 0xb000: 11, ... }
	//
	// This gives a better statistic that is pretty good(tm).
	std::vector<HistReturn> getProbableSboxBits(size_t sbox_index, const std::map<uint16_t, std::map<uint16_t, size_t>>& sbox_state_to_key_hist) const;

	// This function does the following:
	//		- generate path to the round we want (using genPath function)
	//		- direction of the path is based on round_num (0 - forward, 1 - FORBIDDEN, 2 to 4 - backward)
	//		- there may be multiple paths with the same probability => it combines their histograms into one
	std::map<uint16_t, size_t> getProbableSubkey(size_t round_num, const SboxState& wanted_sbox) const;

	// Generate input differences for the round we want that satisfy the wanted_sbox mask.
	// Then we work backwards/forwards using findPathForRound.
	std::vector<Path> genPath(size_t round_num, const SboxState& wanted_sbox, bool forward = false) const;

	// Given an input difference, find the best possible input difference for the round up (when going backwards) or down (forwards).
	// This is achieved by looking through the diff table (normal - when going backwards, transposed - forwards) and looking for
	// for the best differential.
	uint16_t findPathForRound(size_t round_num, uint16_t prev_round_in_diff, double& probability, bool forward = false) const;
	
	// Decryption functions that are looking for the most probable subkey for a given path
	//		- generate PC pairs with the given path input difference
	//		- return a histogram of key: count
	//
	// Only getProbableMiddleSubkey is multi-threaded for a very, very good reason.
	std::map<uint16_t, size_t> getProbableFirstSubkey(const Path& path) const;
	std::map<uint16_t, size_t> getProbableLastSubkey(const Path& path) const;
	std::map<uint16_t, size_t> getProbableMiddleSubkey(size_t round_num, const Path& path, bool forward = false) const;

	std::vector<uint16_t> genPCPair(uint16_t input_diff, bool forward = false) const;
	// Thanks PeterM, my vector function was worse
	std::set<uint16_t> genSubkeysSet(uint16_t mask) const;
	std::vector<Path> findBestPaths(const std::vector<Path>& paths) const;
	std::vector<HistReturn> findMaxInHist(const std::map<uint16_t, size_t>& hist) const;
};