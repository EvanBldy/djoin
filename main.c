#include <stdio.h>
#include <stdlib.h>

#include "lib/djoinutils.h"

//Main program

int main(int argc, char *argv[])
{
    struct djoin_info *dinfo;
	if (argv[1]!=NULL) {
	    dinfo=djoin_read_domain_file(argv[1]);
		if (dinfo==NULL)
			return EXIT_FAILURE;
		djoin_print_domain_info(dinfo);
	}
	else {
		printf("You did not specify a file as an argument\n");
		return EXIT_FAILURE;
	}
    return EXIT_SUCCESS;
}