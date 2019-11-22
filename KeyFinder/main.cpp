// main.cpp
// Author: Michal Malik
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
// Last subkey recovery algorithm by http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf
//
#include "keyfinder.hpp"
#include "cxxopts.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>


int main(int argc, char** argv)
{
	std::string ciphertext_list_filename;
	std::string sbox;

	// "Heuristics"
	bool compute_3_sboxes = false;
	bool compute_4_sboxes = false;

	size_t num_of_threads = KeyFinder::DEFAULT_NUM_OF_THREADS;

	// Mode
	bool first_subkey_only = false;
	bool last_subkey_only = false;
	std::vector<std::string> backward_subkeys;
	bool find_all_subkeys = false;
	bool print_diff_table = false;
	std::string given_key;
	
	int verbose = KeyFinder::VerboseLevel::VERBOSE_NONE;

	try
	{
		cxxopts::Options options(argv[0],
			"KeyFinder by Michal Malik, implemented for 'Design and analysis of ciphers' at FEI STU, Bratislava\n\n"
			"This tool can recover the WHOLE KEY with differential cryptanalysis of a basic SPN cipher:\n"
			"\t- 4x4 S-box\n"
			"\t- 5 rounds\n"
			"\t- 80-bit key, 16-bit subkey for each round\n"
			"\t- input & output is 16 bits\n\n"
			"Inspired by this tutorial http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf\n\n"
			"Use like so to recover the whole key: KeyFinder <ciphertexts> <sbox> -a -t <threads>\n");
		options.positional_help("<CIPHERTEXT_LIST> <SBOX>").show_positional_help();

		options
			.allow_unrecognised_options()
			.add_options()
			("h,help", "Print help")
			("v,verbose",
				"Print more descriptive messages."
				" 1 = more info, 2 = medium info, 3 = VERY detailed",
				cxxopts::value<int>(verbose), "N")
			("ciphertext_list",
				"List of ciphertexts, each line in hhhh format.",
				cxxopts::value<std::string>(ciphertext_list_filename), "filename")
			("sbox",
				"Space separated decimal values <0,15> for sbox, e.g: \"6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9\"",
				cxxopts::value<std::string>(sbox))
			("t,threads",
				"Number of threads to use (default: " + std::to_string(num_of_threads) + ")",
				cxxopts::value<size_t>(num_of_threads), "N")
			("heur3",
				"Use 3 sboxes for subkey computation when generating best paths."
				" More accurate than just 2 sboxes (default), but ~10x slower.",
				cxxopts::value<bool>(compute_3_sboxes))
			("heur4",
				"Use 4 sboxes for subkey computation when generating best paths."
				" Best accuracy, but takes ~5x longer than 3 sboxes."
				" This enables --heur3 as well.",
				cxxopts::value<bool>(compute_4_sboxes));

		options.add_options("Mode")
			("f,first", "Calculate first subkey only", cxxopts::value<bool>(first_subkey_only))
			("l,last", "Calculate last subkey only", cxxopts::value<bool>(last_subkey_only))
			("backward",
				"Used to calculate a specific subkey (backward). Next one after given will be calculated."
				" List of comma-separated subkeys to use (before the one(s) you want, going from right to left), last subkey first, format hhhh.",
				cxxopts::value<std::vector<std::string>>(), "key5,key4,..")
			("a,find-all",
				"Try to find all subkeys. This enables Heur3 and Heur4. CAUTION: THIS TAKES A LONG TIME!", cxxopts::value<bool>(find_all_subkeys))
			("test-key",
				"Given a key in aaaabbbbccccddddeeee format, test if encrypting plaintexts results in given ciphertexts",
				cxxopts::value<std::string>(given_key), "key")
			("d,diff-table",
				"Print diff table for the given sbox",
				cxxopts::value<bool>(print_diff_table));

		options.parse_positional({ "ciphertext_list", "sbox" });
		auto result = options.parse(argc, argv);

		if (result.count("help"))
		{
			std::cerr << options.help() << '\n';
			exit(0);
		}

		if (!result.count("ciphertext_list"))
		{
			std::cerr << options.help() << '\n';
			exit(0);
		}

		if (!result.count("sbox"))
		{
			std::cerr << options.help() << '\n';
			exit(0);
		}

		if (result.count("backward"))
		{
			const auto &v = result["backward"].as<std::vector<std::string>>();
			for (const auto& s : v)
			{
				backward_subkeys.push_back(s);
			}
		}

		if (result.count("find-all"))
		{
			compute_3_sboxes = true;
			compute_4_sboxes = true;
		}

		if (result.count("heur4"))
		{
			compute_3_sboxes = true;
		}
	}
	catch (const cxxopts::OptionException& e)
	{
		std::cout << "Error parsing options: " << e.what() << '\n';
		return EXIT_FAILURE;
	}

	SPN spn;
	spn.setSboxes(const_cast<char*>(sbox.c_str()));
	spn.calculateDiffTable();

	KeyFinder finder(ciphertext_list_filename, spn, num_of_threads, compute_3_sboxes, compute_4_sboxes);
	finder.setVerbose(verbose);

	std::cerr << "will use " << num_of_threads << " thread(s)\n";

	if (compute_3_sboxes)
	{
		std::cerr << "will use 3 sboxes!\n";
	}

	if (compute_4_sboxes)
	{
		std::cerr << "will use 4 sboxes!\n";
	}

	if (first_subkey_only)
	{
		uint16_t key0 = finder.recoverFirstSubkey();
		printf("%04hx\n", key0);
		finder.getSubkeys()[0] = key0;
	}
	else if (last_subkey_only)
	{
		uint16_t k4 = finder.recoverLastSubkey();
		printf("%04hx\n", k4);
		finder.getSubkeys()[SPN::Nr] = k4;
	}
	else if (!backward_subkeys.empty())
	{
		size_t i = 0;
		for (i = 0; i < backward_subkeys.size(); ++i)
		{
			uint16_t key = 0;
			if (sscanf(backward_subkeys[i].c_str(), "%04hx", &key) != 1)
			{
				std::cout << "cant parse key in list: " << backward_subkeys[i] << '\n';
				return EXIT_FAILURE;
			}

			finder.getSubkeys()[SPN::Nr - i] = key;
			fprintf(stderr, "using a given key[%zd]=%04hx\n", SPN::Nr - i, key);
		}

		auto start = std::chrono::steady_clock::now();

		size_t wanted_key_index = SPN::Nr - i;
		fprintf(stderr, "wanted key[%zd]\n", wanted_key_index);

		if (wanted_key_index <= 1)
		{
			std::cout << "this does not work for key[0], key[1] properly, use another method\n";
			return EXIT_FAILURE;
		}

		fprintf(stderr, "starting key[%zd] recovery\n", wanted_key_index);
		uint16_t key = finder.recoverRoundSubkey(wanted_key_index);
		finder.getSubkeys()[wanted_key_index] = key;
		printf("key[%zd] = %04hx\n", wanted_key_index, key);

		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
		std::cerr << "took: " << elapsed.count() / 1000.0f << "s\n";
	}
	else if (find_all_subkeys)
	{
		auto start = std::chrono::steady_clock::now();

		std::cerr << "starting full key recovery..\n";

		uint16_t key4 = finder.recoverLastSubkey();
		finder.getSubkeys()[SPN::Nr] = key4;

		fprintf(stderr, "key[%zd]=%04hx\n", SPN::Nr, key4);

		// Dont ever do round >= 1 here
		for (size_t round = SPN::Nr - 1; round > 1; --round)
		{
			uint16_t subkey = finder.recoverRoundSubkey(round);
			finder.getSubkeys()[round] = subkey;
			fprintf(stderr, "key[%zd]=%04hx\n", round, subkey);
		}

		uint16_t key0 = finder.recoverFirstSubkey();
		finder.getSubkeys()[0] = key0;

		fprintf(stderr, "key[0]=%04hx\n", key0);

		uint16_t key1 = finder.recoverSecondSubkey();
		finder.getSubkeys()[1] = key1;

		fprintf(stderr, "key[1]=%04hx\n", key1);

		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
		std::cerr << "took: " << elapsed.count() / 1000.0f << "s\n";

		std::cout << "full key: " << finder.getKeyStr() << '\n';
	}
	else if (!given_key.empty())
	{
		spn.keysched(given_key.c_str());

		const auto& pc = finder.getPCPairs();

		bool ok = true;
		for (size_t i = 0; i < pc.size(); ++i)
		{
			if (spn.encrypt(static_cast<uint16_t>(i)) != pc[i])
			{
				ok = false;
				break;
			}
		}

		if (ok)
		{
			std::cerr << "key is ok\n";
		}
		else
		{
			std::cerr << "key is wrong\n";
			return EXIT_FAILURE;
		}
	}
	else if (print_diff_table)
	{
		const auto& diff_table = finder.getDiffTable();

		for (auto x : diff_table)
		{
			for (auto y : x)
			{
				printf("%2d ", y);
			}

			putchar('\n');
		}
	}
	else
	{
		std::cerr << "Nothing to do.. use -h\n";
	}

	return EXIT_SUCCESS;
}