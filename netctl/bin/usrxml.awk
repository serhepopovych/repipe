#!/usr/bin/gawk -f

# Source USRXML database parsing library.
@include "@target@/netctl/lib/awk/libusrxml.awk"

################################################################################

function print_usrxml_entry_pipe(h, userid, file,    n, i, j, p, a, cmd, line, ret, errstr)
{
	# h,userid
	i = h SUBSEP userid;

	cmd = "@target@/netctl/bin/shapers " USRXML_users[i];
	errstr = "";

	# pipe
	p = 0 + USRXML_userpipe[i];

	while ((ret = (cmd | getline line)) > 0) {
		n = split(line, a, " ");
		if (n == 3) {
			# h,userid,pipeid
			j = i SUBSEP p;

			## Valid policy in format: "zone dir bw"

			# Skip "Kb" at the end
			sub("Kb$", "", a[3]);

			USRXML_userpipe[j] = ++p;
			USRXML_userpipe[j,"zone"] = a[1];
			USRXML_userpipe[j,"dir"] = a[2];
			USRXML_userpipe[j,"bw"] = a[3];
		} else if (n == 0) {
			## No fields: may be empty line, skip
			continue;
		} else if (n == 1 && a[1] == "none") {
			# Single field: "none"
			break;
		} else {
			## Unknown format: failure
			errstr = sprintf("%s: shapers unknown format",
					 USRXML_users[i]);
			ret = USRXML_E_GETLINE;
			break;
		}
	}
	close(cmd);

	if (ret < 0) {
		if (errstr == "") {
			errstr = sprintf("%s: pipe read error: %s",
					 USRXML_users[i], ERRNO);
		}
		usrxml_result(h, USRXML_E_GETLINE, USRXML_MSG_PRIO_ERR, errstr);
		usrxml_clearerrno(h);
	} else {
		USRXML_userpipe[i] = p;
		print_usrxml_entry(h, userid, file);
	}

	# Ignore errors to continue on next entry
	return userid + 1;
}

BEGIN{
	##
	## Initialize user database parser.
	##
	h = init_usrxml_parser("repipe")
	if (h < 0)
		exit 1;
}

{
	##
	## Parse user database.
	##
	line = $0;
	if (run_usrxml_parser(h, line, "print_usrxml_entry_pipe") < 0)
		exit 1;
}

END{
	##
	## Finish user database parsing.
	##
	if (fini_usrxml_parser(h) < 0)
		exit 1;
}
