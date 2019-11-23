// keyfinder.cpp
// Author: Michal Malik
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
// Last subkey recovery algorithm by http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf
//
#include "keyfinder.hpp"

#include <fstream>
#include <string>
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>


KeyFinder::KeyFinder(const std::string& ct_file, SPN& spn, size_t num_of_threads, bool compute_3_sboxes, bool compute_4_sboxes) :
	m_spn{ spn },
	m_pc1_forward { std::vector<uint16_t>(65536, 0) },
	m_subkeys{ std::vector<uint16_t>(SPN::Nr + 1, 0) },
	m_compute_3_sboxes{ compute_3_sboxes },
	m_compute_4_sboxes{ compute_4_sboxes },
	m_num_of_threads{ num_of_threads }
{
	std::ifstream ct_list(ct_file);
	if (!ct_list.is_open())
	{
		std::cerr << "could not open file " << ct_file << '\n';
		exit(0xdeadf00d);
	}

	std::string line;
	uint16_t pt = 0;
	while (std::getline(ct_list, line))
	{
		uint16_t ct = 0;
		if (sscanf(line.c_str(), "%04hx", &ct) != 1)
		{
			std::cerr << "could not parse line\n";
			exit(0xcafebabe);
		}

		m_pc1.push_back(ct);
		m_pc1_forward[ct] = pt++;
	}
}


std::string KeyFinder::getKeyStr() const
{
	std::string key;

	for (uint16_t subkey : m_subkeys)
	{
		char in_hex[5] = { 0 };
		snprintf(in_hex, sizeof(in_hex), "%04hx", subkey);
		key += in_hex;
	}

	return key;
}


bool KeyFinder::testKey(const std::string& key) const
{
	m_spn.keysched(key.c_str());

	for (size_t i = 0; i < m_pc1.size(); ++i)
	{
		if (m_spn.encrypt(static_cast<uint16_t>(i)) != m_pc1[i])
		{
			return false;
		}
	}

	return true;
}


uint16_t KeyFinder::recoverFirstSubkey()
{
	if (m_compute_3_sboxes || m_compute_4_sboxes)
	{
		if (m_verbose)
		{
			fprintf(stderr, "turning off 3 and 4 sboxes for key[0] for performance reasons\n");
		}

		m_compute_3_sboxes = false;
		m_compute_4_sboxes = false;
	}

	uint16_t subkey = recoverRoundSubkey(0);

	m_compute_3_sboxes = true;
	m_compute_4_sboxes = true;

	return subkey;
}


uint16_t KeyFinder::recoverSecondSubkey() const
{
	std::cerr << "looking for key[1]..\n";

	auto start = std::chrono::steady_clock::now();

	std::vector<uint16_t> subkeys = m_subkeys;
	uint16_t key1 = 0;
	for (uint32_t x = 0; x <= 0xffff; ++x)
	{
		subkeys[1] = x;
		uint16_t ct = m_pc1[x];
		if (m_spn.decryptWithKeys(ct, subkeys) == x)
		{
			fprintf(stderr, "found key[1] = %04hx\n", static_cast<uint16_t>(x));
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
			std::cerr << "took: " << elapsed.count() / 1000.0f << "s\n";

			return x;
		}
	}

	if (m_verbose)
	{
		std::cerr << "could not find key[1]\n";
		exit(0xbabebabe);
	}

	return key1;
}


uint16_t KeyFinder::recoverLastSubkey()
{
	if (m_compute_3_sboxes || m_compute_4_sboxes)
	{
		if (m_verbose)
		{
			fprintf(stderr, "turning off 3 and 4 sboxes for key[0] for performance reasons\n");
		}

		m_compute_3_sboxes = false;
		m_compute_4_sboxes = false;
	}

	uint16_t subkey = recoverRoundSubkey(4);

	m_compute_3_sboxes = true;
	m_compute_4_sboxes = true;

	return subkey;
}


uint16_t KeyFinder::recoverRoundSubkey(size_t round_num) const
{
	// If you use this function with round_num = 1, you deserve what's coming
	std::cerr << "guessing key[" << round_num << "]..\n";
	auto start = std::chrono::steady_clock::now();

	std::map<uint16_t, std::map<uint16_t, size_t>> sbox_state_to_key_hist;
	for (uint16_t state = 1; state <= 0xf; ++state)
	{
		SboxState s(state);

		switch (s.active.count())
		{
		case 1:
		case 2:
		{
			sbox_state_to_key_hist.insert(std::make_pair(state, getProbableSubkey(round_num, s)));
			break;
		}
		case 3:
		{
			if (m_compute_3_sboxes)
			{
				fprintf(stderr, "doing 3 sboxes for key[%zd]\n", round_num);
				sbox_state_to_key_hist.insert(std::make_pair(state, getProbableSubkey(round_num, s)));
			}
			break;
		}
		case 4:
		{
			if (m_compute_4_sboxes)
			{
				fprintf(stderr, "doing 4 sboxes for key[%zd]\n", round_num);
				sbox_state_to_key_hist.insert(std::make_pair(state, getProbableSubkey(round_num, s)));
			}
			break;
		}
		default:
		{
			// This should never happen
			break;
		}
		}
	}

	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
	std::cerr << "took: " << elapsed.count() / 1000.0f << "s\n";

	uint16_t subkey = 0;

	auto bits_12_15 = getProbableSboxBits(0, sbox_state_to_key_hist);
	if (bits_12_15.size() > 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "potential key[%zd] bits 12-15 values:\n", round_num);
			for (const auto& p : bits_12_15)
			{
				fprintf(stderr, "\tkey=%04hx, count=%zd\n", p.key, p.value);
			}

			std::cerr << "using the first one\n";
		}

		subkey |= bits_12_15[0].key;
	}
	else if (bits_12_15.size() == 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "found key[%zd] bits 12-15: %04hx\n", round_num, bits_12_15[0].key);
		}

		subkey |= bits_12_15[0].key;
	}
	else
	{
		fprintf(stderr, "no key[%zd] bits 12-15 could be guessed, this is probably a bug", round_num);
		exit(0xdeadbabe);
	}

	auto bits_8_11 = getProbableSboxBits(1, sbox_state_to_key_hist);
	if (bits_8_11.size() > 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "potential key[%zd] bits 8-11 values:\n", round_num);
			for (const auto& p : bits_8_11)
			{
				fprintf(stderr, "\tkey=%04hx, count=%zd\n", p.key, p.value);
			}

			std::cerr << "using the first one\n";
		}

		subkey |= bits_8_11[0].key;
	}
	else if (bits_8_11.size() == 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "found key[%zd] bits 8-11: %04hx\n", round_num, bits_8_11[0].key);
		}

		subkey |= bits_8_11[0].key;
	}
	else
	{
		fprintf(stderr, "no key[%zd] bits 8-11 could be guessed, this is probably a bug", round_num);
		exit(0xdeadbabe);
	}

	auto bits_4_7 = getProbableSboxBits(2, sbox_state_to_key_hist);
	if (bits_4_7.size() > 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "potential key[%zd] bits 4-7 values:\n", round_num);
			for (const auto& p : bits_4_7)
			{
				fprintf(stderr, "\tkey=%04hx, count=%zd\n", p.key, p.value);
			}

			std::cerr << "using the first one\n";
		}

		subkey |= bits_4_7[0].key;
	}
	else if (bits_4_7.size() == 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "found key[%zd] bits 4-7: %04hx\n", round_num, bits_4_7[0].key);
		}

		subkey |= bits_4_7[0].key;
	}
	else
	{
		fprintf(stderr, "no key[%zd] bits 4-7 could be guessed, this is probably a bug", round_num);
		exit(0xdeadbabe);
	}

	auto bits_0_3 = getProbableSboxBits(3, sbox_state_to_key_hist);
	if (bits_0_3.size() > 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "potential key[%zd] bits 0-3 values:\n", round_num);
			for (const auto& p : bits_0_3)
			{
				fprintf(stderr, "\tkey=%04hx, count=%zd\n", p.key, p.value);
			}

			std::cerr << "using the first one\n";
		}

		subkey |= bits_0_3[0].key;
	}
	else if (bits_0_3.size() == 1)
	{
		if (m_verbose)
		{
			fprintf(stderr, "found key[%zd] bits 0-3: %04hx\n", round_num, bits_0_3[0].key);
		}

		subkey |= bits_0_3[0].key;
	}
	else
	{
		fprintf(stderr, "no key[%zd] bits 0-3 could be guessed, this is probably a bug", round_num);
		exit(0xdeadbabe);
	}

	fprintf(stderr, "guessed key[%zd] = %04hx\n", round_num, subkey);

	return subkey;
}


std::vector<KeyFinder::HistReturn> KeyFinder::getProbableSboxBits(size_t sbox_index, const std::map<uint16_t, std::map<uint16_t, size_t>>& sbox_state_to_key_hist) const
{
	std::map<uint16_t, size_t> main = sbox_state_to_key_hist.at((1 << (3 - sbox_index)));

	for (const auto& p : sbox_state_to_key_hist)
	{
		SboxState s(p.first);

		// Don't do a configuration that doesn't have the wanted sbox active
		// So, if we want sbox 0 active, don't pick 0b0001 etc.
		if (s.active.count() < 2 || !s.active[3 - sbox_index])
		{
			continue;
		}

		// Combine their statistics with masked key for what we want
		auto res = findMaxInHist(p.second);
		for (const HistReturn& r : res)
		{
			main[r.key & SboxMask(sbox_index)] += r.value;
		}
	}

	return findMaxInHist(main);
}


std::map<uint16_t, size_t> KeyFinder::getProbableSubkey(size_t round_num, const SboxState &wanted_sbox) const
{
	// If we want 0th subkey, round number is 4 because we are going backwards
	bool forward = false;
	size_t path_round_num = round_num;

	// Note: this should happen for <= 1, but it doesn't work, so eh
	if (round_num == 0)
	{
		forward = true;
		path_round_num = SPN::Nr - round_num;
	}

	auto paths = findBestPaths(genPath(path_round_num, wanted_sbox, forward));

	if (m_verbose)
	{
		fprintf(stderr, "processing paths to sboxes %04hx in round %zd: %zd\n", wanted_sbox.mask, round_num, paths.size());
	}

	size_t processed = 0;
	size_t quantum = (paths.size() / 10) + 1;

	std::map<uint16_t, size_t> probable_keys;
	for (const auto& path : paths)
	{
		if ((processed % quantum) == 0 && m_verbose)
		{
			fprintf(stderr, "processed: %zd/%zd\n", processed, paths.size());
		}

		if (m_verbose >= VERBOSE_MEDIUM)
		{
			fprintf(stderr, "path input=%04hx, output=%04hx, mask=%04hx, prob=%lf\n", path.input_diff, path.output_diff, Mask(path.output_diff), path.probability);
		}
		
		std::map<uint16_t, size_t> hist;
		switch (round_num)
		{
		case 4:
		{
			hist = getProbableLastSubkey(path);
			break;
		}
		case 3:
		case 2:
		case 1:
		{
			hist = getProbableMiddleSubkey(path_round_num, path, forward);
			break;
		}
		case 0:
		{
			hist = getProbableFirstSubkey(path);
			break;
		}
		default:
		{
			// This should never happen
			break;
		}
		}

		auto res = findMaxInHist(hist);
		for (HistReturn h : res)
		{
			probable_keys[h.key] += h.value;
		}

		++processed;
	}

	if (m_verbose)
	{
		fprintf(stderr, "processed: %zd/%zd\n", processed, paths.size());
	}
	
	return probable_keys;
}


std::vector<KeyFinder::Path> KeyFinder::genPath(size_t from_round, const SboxState& wanted_sbox, bool forward) const
{
	std::set<uint16_t> wanted_round_in_diffs;
	// Go through all possible values of input differences in the wanted round where only wanted sboxes are active
	// Mask magic is ensuring that for example for Sbox 0b1010 (first active, third active), we don't generate an input difference like so:
	//		0050
	//		f000
	//		0000
	for (uint16_t u : genSubkeysSet(wanted_sbox.mask))
	{
		bool ok = true;
		for (uint16_t m : wanted_sbox.aux_masks)
		{
			if ((u & m) == 0)
			{
				ok = false;
				break;
			}
		}

		if (!ok || (u & ~wanted_sbox.mask) != 0)
		{
			continue;
		}

		wanted_round_in_diffs.insert(u);
	}

	std::vector<Path> paths;
	for (uint16_t u : wanted_round_in_diffs)
	{
		if (m_verbose == VERBOSE_VERY)
		{
			fprintf(stderr, "v%zd=%04hx u%zd=%04hx\n", from_round - 1, m_spn.itransp(u), from_round, u);
		}

		uint16_t prev_round_in_diff = u;
		double probability = 1.0f;
		// from_round - 1 because we already did one round
		for (size_t r = from_round - 1; r >= 1; --r)
		{
			uint16_t round_in_diff = findPathForRound(r, prev_round_in_diff, probability, forward);
			prev_round_in_diff = round_in_diff;
		}

		if (m_verbose == VERBOSE_VERY)
		{
			fprintf(stderr, "input diff: %04hx (%04hx)\n", prev_round_in_diff, Mask(prev_round_in_diff));
			fprintf(stderr, "output diff: %04hx\n", u);
			fprintf(stderr, "probability: %lf\n", probability);
			std::cerr << "-------------\n";
		}

		paths.push_back(Path(prev_round_in_diff, u, probability));
	}

	return paths;
}


uint16_t KeyFinder::findPathForRound(size_t round_num, uint16_t prev_round_in_diff, double &probability, bool forward) const
{
	const auto& diff_table = forward ? m_spn.getTransposedDiffTable() : m_spn.getDiffTable();

	uint16_t round_out_diff = m_spn.itransp(prev_round_in_diff);
	uint16_t round_in_diff = 0;

	if (m_verbose == VERBOSE_VERY)
	{
		fprintf(stderr, "round %zd:\n", round_num);
		fprintf(stderr, "\tv%zd=%04hx\n", round_num, round_out_diff);
	}

	for (uint16_t sbox_index : FindSbox(round_out_diff))
	{
		std::vector<uint16_t> new_dxs;

		uint16_t max_distrib = 0;
		for (uint16_t dx = 1; dx <= 0xf; ++dx)
		{
			uint16_t d = diff_table[dx][SboxValue(sbox_index, round_out_diff)];
			if (d > max_distrib)
			{
				max_distrib = d;
			}
		}

		probability *= (max_distrib / 16.0f);

		for (uint16_t dx = 1; dx <= 0xf; ++dx)
		{
			if (diff_table[dx][SboxValue(sbox_index, round_out_diff)] == max_distrib)
			{
				new_dxs.push_back(dx);
			}
		}

		// There's multiple dx values to choose. Whatever is chosen influences active sboxes in the 
		// next round. We try to minimize the number of active sboxes.
		//
		//v3 = 00a0 u4 = 2020
		//	round 3:
		//	v3 = 00a0
		//	sbox = 2, dx = 4, dy = 10, round_in_diff = 0040, next_out_diff = 0200, count_in_next = 1
		//	sbox = 2, dx = 11, dy = 10, round_in_diff = 00f0, next_out_diff = 2222, count_in_next = 4
		//	u3 = 0040
		//	round 2:
		//	v2 = 0200
		//
		// If we picked dx=11, dy=10 for sbox=2, current round input diff would be 000f0, which would cause the next round output diff
		// be 0x2222 (because transposing 0x00f0 results in 0x2222) => 4 active sboxes
		//
		// If we picked dx=4, dy=10, round input diff would be 0x0040 => next output diff 0x2000 => 1 active sbox
		//
		// Note: this always happens to be the first one, so this cycle is a bit useless, but disregard this information for now..

		// Lowest count of next active sboxes
		size_t lowest_active_count = 5;
		for (uint16_t dx : new_dxs)
		{
			uint16_t potential_round_in_diff = round_in_diff | MakeSbox(sbox_index, dx);
			uint16_t next_round_out_diff = m_spn.itransp(potential_round_in_diff);
			size_t next_out_active_count = SboxCount(next_round_out_diff);

			if (m_verbose == VERBOSE_VERY)
			{
				fprintf(stderr, "\tsbox=%d, dx=%d, dy=%d, distrib=%d, round_in_diff=%04hx, next_out_diff=%04hx, active_count_in_next=%zd\n",
					sbox_index,
					dx,
					SboxValue(sbox_index, round_out_diff),
					max_distrib,
					potential_round_in_diff,
					next_round_out_diff,
					next_out_active_count);
			}

			if (next_out_active_count < lowest_active_count)
			{
				lowest_active_count = next_out_active_count;
				round_in_diff = potential_round_in_diff;
			}
		}

		if (m_verbose == VERBOSE_VERY)
		{
			fprintf(stderr, "\tusing lowest count %zd for sbox=%d\n", lowest_active_count, sbox_index);
		}
	}
	
	if (m_verbose == VERBOSE_VERY)
	{
		fprintf(stderr, "\tu%zd=%04hx\n", round_num, round_in_diff);
	}

	return round_in_diff;
}


std::map<uint16_t, size_t> KeyFinder::getProbableFirstSubkey(const Path& path) const
{
	std::vector<uint16_t> pc2 = genPCPair(path.input_diff, true); // Change 1
	uint16_t output_mask = Mask(path.output_diff);
	const auto subkeys = genSubkeysSet(output_mask);

	std::map<uint16_t, size_t> hist;
	size_t num = 0;
	for (size_t i = 0; i < m_pc1_forward.size(); ++i) // Change 2
	{
		uint16_t ct1 = m_pc1_forward[i]; // Change 3
		uint16_t ct2 = pc2[i];

		if ((ct1 & (~output_mask)) != (ct2 & (~output_mask)))
		{
			continue;
		}

		++num;

		for (uint16_t sk : subkeys)
		{
			uint16_t v1 = ct1 ^ sk;
			uint16_t v2 = ct2 ^ sk;
			uint16_t u1 = m_spn.subst(v1); // Change 4
			uint16_t u2 = m_spn.subst(v2); // Change 5

			if (((u1 ^ u2) & output_mask) == path.output_diff)
			{
				hist[sk] += 1;
			}
		}
	}

	if (m_verbose >= VERBOSE_MEDIUM)
	{
		fprintf(stderr, "valid pc pairs: %zd\n", num);
	}

	return hist;
}


std::map<uint16_t, size_t> KeyFinder::getProbableLastSubkey(const Path& path) const
{
	std::vector<uint16_t> pc2 = genPCPair(path.input_diff);
	uint16_t output_mask = Mask(path.output_diff);
	const auto subkeys = genSubkeysSet(output_mask);

	std::map<uint16_t, size_t> hist;
	size_t num = 0;
	for (size_t i = 0; i < m_pc1.size(); ++i)
	{
		uint16_t ct1 = m_pc1[i];
		uint16_t ct2 = pc2[i];

		if ((ct1 & (~output_mask)) != (ct2 & (~output_mask)))
		{
			continue;
		}

		++num;

		for (uint16_t sk : subkeys)
		{
			uint16_t v1 = ct1 ^ sk;
			uint16_t v2 = ct2 ^ sk;
			uint16_t u1 = m_spn.isubst(v1);
			uint16_t u2 = m_spn.isubst(v2);

			if (((u1 ^ u2) & output_mask) == path.output_diff)
			{
				hist[sk] += 1;
			}
		}
	}

	if (m_verbose >= VERBOSE_MEDIUM)
	{
		fprintf(stderr, "valid pc pairs: %zd\n", num);
	}

	return hist;
}


std::map<uint16_t, size_t> KeyFinder::getProbableMiddleSubkey(size_t round_num, const Path& path, bool forward) const
{
	std::vector<uint16_t> pc2 = genPCPair(path.input_diff, forward);
	uint16_t output_mask = Mask(path.output_diff);
	const auto subkeys = genSubkeysSet(output_mask);

	std::map<uint16_t, size_t> hist;
	const auto& main_pc = forward ? m_pc1_forward : m_pc1;

	size_t n_threads = m_num_of_threads;
	size_t start = 0;
	size_t per_thread_work = main_pc.size() / n_threads;
	size_t end = per_thread_work;
	std::mutex mutex;

	std::vector<std::thread> workers;
	for (size_t i = 0; i < n_threads; ++i)
	{
		std::thread t(
			[this, &mutex, main_pc, pc2, subkeys, path, round_num, forward, start, end, &hist]
			{
				uint16_t output_mask = Mask(path.output_diff);
				std::map<uint16_t, size_t> my_hist;

				// WARNING: it's broken if forward = true
				//
				//
				if (forward)
				{
					for (size_t i = start; i < end; ++i)
					{
						uint16_t ct1 = m_spn.subst(main_pc[i] ^ m_subkeys[SPN::Nr]);
						uint16_t ct2 = m_spn.subst(pc2[i] ^ m_subkeys[SPN::Nr]);

						//for (size_t i = SPN::Nr - 1; i > round_num; --i)
						//{
						//	ct1 ^= m_subkeys[i];
						//	ct1 = m_spn.itransp(ct1);
						//	ct1 = m_spn.subst(ct1);

						//	ct2 ^= m_subkeys[i];
						//	ct2 = m_spn.itransp(ct2);
						//	ct2 = m_spn.subst(ct2);
						//}

						if ((ct1 & ~output_mask) != (ct2 & ~output_mask))
						{
							continue;
						}

						for (uint16_t sk : subkeys)
						{
							uint16_t u1 = m_spn.subst(m_spn.itransp(ct1 ^ sk));
							uint16_t u2 = m_spn.subst(m_spn.itransp(ct2 ^ sk));

							if (((u1 ^ u2) & output_mask) == path.output_diff)
							{
								my_hist[sk] += 1;
							}
						}
					}
				}
				else
				{
					for (size_t i = start; i < end; ++i)
					{
						uint16_t ct1 = m_spn.isubst(main_pc[i] ^ m_subkeys[SPN::Nr]);
						uint16_t ct2 = m_spn.isubst(pc2[i] ^ m_subkeys[SPN::Nr]);

						for (size_t i = SPN::Nr - 1; i > round_num; --i)
						{
							ct1 ^= m_subkeys[i];
							ct1 = m_spn.isubst(m_spn.itransp(ct1));

							ct2 ^= m_subkeys[i];
							ct2 = m_spn.isubst(m_spn.itransp(ct2));
						}

						if ((ct1 & ~output_mask) != (ct2 & ~output_mask))
						{
							continue;
						}

						for (uint16_t sk : subkeys)
						{
							uint16_t u1 = m_spn.isubst(m_spn.itransp(ct1 ^ sk));
							uint16_t u2 = m_spn.isubst(m_spn.itransp(ct2 ^ sk));

							if (((u1 ^ u2) & output_mask) == path.output_diff)
							{
								my_hist[sk] += 1;
							}
						}
					}
				}

				mutex.lock();
				for (const auto& p : my_hist)
				{
					hist[p.first] += p.second;
				}
				mutex.unlock();
			});


		workers.push_back(std::move(t));
		start = end;
		end += per_thread_work;
	}

	for (std::thread& t : workers)
	{
		t.join();
	}

	return hist;
}


std::vector<uint16_t> KeyFinder::genPCPair(uint16_t input_diff, bool forward) const
{
	const auto& main = forward ? m_pc1_forward : m_pc1;

	std::vector<uint16_t> pc;
	for (size_t i = 0; i < main.size(); ++i)
	{
		pc.push_back(main[static_cast<uint16_t>(i) ^ input_diff]);
	}

	return pc;
}


std::set<uint16_t> KeyFinder::genSubkeysSet(uint16_t mask) const
{
	std::set<uint16_t> subkeys;

	for (size_t i = 0; i < 16; i += 4)
	{
		if ((mask & (0x000f << i)) == 0)
		{
			continue;
		}

		for (uint16_t nibble = 0; nibble <= 0xf; nibble++)
		{
			uint16_t subkey = nibble << i;
			for (uint16_t x : subkeys)
			{
				subkeys.insert(x | subkey);
			}

			subkeys.insert(subkey);
		}
	}

	return subkeys;
}


std::vector<KeyFinder::Path> KeyFinder::findBestPaths(const std::vector<Path>& paths) const
{
	double best_probability = 0.0f;

	for (const auto& path : paths)
	{
		if (path.probability > best_probability)
		{
			best_probability = path.probability;
		}
	}

	std::vector<Path> best_paths;
	for (const auto& path : paths)
	{
		if (path.probability == best_probability)
		{
			best_paths.push_back(path);
		}
	}

	return best_paths;
}


std::vector<KeyFinder::HistReturn> KeyFinder::findMaxInHist(const std::map<uint16_t, size_t>& hist) const
{
	size_t max_v = 0;

	for (const auto& p : hist)
	{
		if (p.second > max_v)
		{
			max_v = p.second;
		}
	}

	std::vector<HistReturn> r;
	for (const auto& p : hist)
	{
		if (p.second == max_v)
		{
			r.push_back(HistReturn(p.first, max_v));
		}
	}

	return r;
}
