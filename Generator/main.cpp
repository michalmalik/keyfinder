// main.cpp
// Adapted from code provided for the assignment by prof. Ing. Pavol Zajac, PhD.
// Implemented for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019
//
#include "spn.hpp"

#include <iostream>


int main(int argc, char **argv)
{
	if (argc < 4)
	{
		std::cerr << "usage: <sboxes> <key> <output_file>\n";
		return EXIT_FAILURE;
	}
	
	SPN spn;
	if (!spn.keysched(argv[2]))
	{
		std::cerr << "Error: bad key\n";
		return EXIT_FAILURE;
	}
	
	spn.setSboxes(argv[1]);

	FILE* out = fopen(argv[3], "w+");
	if (out == nullptr)
	{
		std::cerr << "Could not create file\n";
		return EXIT_FAILURE;
	}

	for (uint32_t x = 0; x < 0x10000; x++)
	{
		uint16_t pt = (uint16_t)x;
		uint16_t ct = spn.encrypt(pt);
		uint16_t pt2 = spn.decrypt(ct);

		if (pt != pt2)
		{
			std::cerr << "Error: 0xBAAD\n";
			fclose(out);
			return EXIT_FAILURE;
		}

		fprintf(out, "%04hx\n", ct);
	}

	std::cerr << "ok\n";
	fclose(out);

	return EXIT_SUCCESS;
}