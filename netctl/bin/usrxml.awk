#!/usr/bin/gawk -f

# Source USRXML database parsing library.
@include "@target@/netctl/lib/awk/libusrxml.awk"

################################################################################

BEGIN{
	##
	## Initialize user database parser.
	##
	if (init_usr_xml_parser() < 0)
		exit 1;
}

{
	##
	## Parse user database.
	##
	if (run_usr_xml_parser($0) < 0)
		exit 1;
}

END{
	##
	## Finish user database parsing.
	##
	if (fini_usr_xml_parser() < 0)
		exit 1;

	for (userid = 0; userid < USRXML_nusers; userid++) {
		pipeid = 0;
		cmd = "@target@/netctl/bin/shapers "USRXML_usernames[userid];
		while ((ret = (cmd | getline line)) > 0) {
			nfields = split(line, a, " ");
			if (nfields == 3) {
				## Valid policy in format: "zone dir bw"

				# Skip "Kb" at the end
				sub(/Kb$/, "", a[3]);

				USRXML_userpipezone[userid,pipeid] = a[1];
				USRXML_userpipedir[userid,pipeid] = a[2];
				USRXML_userpipebw[userid,pipeid] = a[3];
			} else if (nfields == 0) {
				## No fields: may be empty line, skip
				continue;
			} else if (nfields == 1 && a[1] == "none") {
				# Single field: "none"
				break;
			} else {
				## Unknown format: failure
				printf "PIPE: get shapers failed " \
					"for user %s\n",
					USRXML_usernames[userid] >"/dev/stderr"
				pipeid = -1;
				break;
			}
			pipeid++;
		}
		if (ret < 0) {
			printf "PIPE: pipe read error: %s\n",
				ERRNO >"/dev/stderr"
			pipeid = -1;
		}
		close(cmd);

		if (pipeid < 0)
			continue;

		USRXML_userpipe[userid] = pipeid;

		print_usr_xml_entry(userid);
	}
}
