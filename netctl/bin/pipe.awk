#!/usr/bin/gawk -f

# Source USRXML database parsing library.
@include "@target@/netctl/lib/awk/libusrxml.awk"

################################################################################

BEGIN{
	##
	## Initialize user database parser.
	##
	h = init_usrxml_parser("pipe.awk", 1);
	if (h < 0)
		exit 1;
}

{
	##
	## Parse user database.
	##
	line = $0;
	if (run_usrxml_parser(h, line) < 0)
		exit 1;
}

END{
	##
	## Data-rate units.
	##

	# SI
	units["kbit"] = 1000;
	units["kbps"] = units["kbit"] * 8;
	units["mbit"] = 1000 * 1000;
	units["mbps"] = units["mbit"] * 8;
	units["gbit"] = 1000 * 1000 * 1000;
	units["gbps"] = units["gbit"] * 8;
	units["tbit"] = 1000 * 1000 * 1000 * 1000;
	units["tbps"] = units["tbit"] * 8;
	# IEC
	units["kibit"] = 1024;
	units["kibps"] = units["kibit"] * 8;
	units["mibit"] = 1024 * 1024;
	units["mibps"] = units["mibit"] * 8;
	units["gibit"] = 1024 * 1024 * 1024;
	units["gibps"] = units["gibit"] * 8;
	units["tibit"] = 1024 * 1024 * 1024 * 1024;
	units["tibps"] = units["tibit"] * 8;

	if (fout)
		print "" >fout;

	prog = USRXML__instance[h,"prog"];

	ifn = USRXML_ifnames[h,"num"];
	for (iff = 0; iff < ifn; iff++) {
		# h,userid
		i = h SUBSEP iff;

		# Skip holes entries
		if (!(i in USRXML_ifnames))
			continue;

		username = USRXML_ifnames[i];

		# Skip inactive users
		if (USRXML_ifnames[h,username,"inactive"])
			continue;

		# h,"orig"
		hh = h USRXML_orig;

		# hh,userid
		i_dst = hh SUBSEP iff;

		usrxml__copy_user_pipe(hh, i_dst, i);
		usrxml__delete_pipe(i, 1);

		cmd = "@target@/netctl/bin/shapers " username;
		while ((ret = (cmd | getline line)) > 0) {
			printf "%s: %s: line: %s\n",
				prog, username, line >"/dev/stderr";

			n = split(line, a, " ");
			if (n == 3) {
				## Valid policy in format: "zone dir bw", apply

				# Translate units to kbit (default is kbit)
				unit = a[3];
				sub("^[[:digit:]]+", "", unit);
				sub(unit "$", "", a[3]);
				unit = toupper(unit);

				if (unit in units)
					a[3] *= units[unit] / units["kbit"];

				# Translate unknown zones to "local"
				if (a[1] != "world" && a[1] != "all")
					a[1] = "local";

				p = USRXML_userpipe[i]++;

				# h,userid,pipeid
				j = i SUBSEP p;

				USRXML_userpipe[j] = p + 1;
				USRXML_userpipe[j,"zone"] = a[1];
				USRXML_userpipe[j,"dir"] = a[2];
				USRXML_userpipe[j,"bw"] = a[3];
			} else if (n == 0) {
				## No fields: may be empty line, skip
			} else if (n == 1 && a[1] == "none") {
				## Valid policy in format: "none", skip
			} else {
				## Unknown format: failure
				break;
			}
		}
		close(cmd);

		m = (i in USRXML_userpipe) ? USRXML_userpipe[i] : 0;

		if (ret || !m || usrxml__scope_validate_pipe(i))
			usrxml__copy_user_pipe(h, i, i_dst);

		usrxml__delete_pipe(i_dst, 1);

		if (ret > 0) {
			printf "%s: %s: get shapers failed\n",
				prog, username >"/dev/stderr";
		} else if (ret < 0) {
			printf "%s: %s: read error: %s\n",
				prog, username, ERRNO >"/dev/stderr";
		} else {
			print_usrxml_entry(h, username, fout);
		}

		# Report final shaper configuration to stderr
		ret = -1;

		m = (i in USRXML_userpipe) ? USRXML_userpipe[i] : 0;

		for (p = 0; p < m; p++) {
			# h,userid,pipeid
			j = i SUBSEP p;

			# Skip hole entries
			if (!(j in USRXML_userpipe))
				continue;

			line = "";
			line = line USRXML_userpipe[j,"zone"] " ";
			line = line USRXML_userpipe[j,"dir"] " ";
			line = line USRXML_userpipe[j,"bw"];

			printf "%s: %s: pipe: %s\n",
				prog, username, line >"/dev/stderr";

			ret = 1;
		}

		if (ret < 0) {
			printf "%s: %s: no shapers\n",
				prog, username >"/dev/stderr";
		}
	}

	##
	## Finish user database parsing.
	##
	if (fini_usrxml_parser(h) < 0)
		exit 1;
}
