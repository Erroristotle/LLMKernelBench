# DONE:

1 - OK
2 - OK
3 - OK
4 - OK
5 - OK
6 - OK
7 - MISSING CODE - Added function __tail_onwire_len
8 - MISSING CODE - Had just a line instead of the entire function - added function
9 - OK
10 - OK
11 - OK
12 - OK
14 - OK
15 - REMOVED - Only Makefile changes
18 - OK
20 - OK
21 - OK
22 - OK
23 - OK
24 - MISSING CODE - Missing set_address_limits function in patched code block
25 - OK
26 - OK
27 - OK
28 - OK
29 - Removed - Only Makefile changes - chatgpt says it is only noise, I am not sure, left it as-is for second opinion
30 - OK
31 - OK
32 - OK
33 - OK
34 - MISSING CODE - Missing code on first and second file
35 - NOISE - Remove one include (not security related)
36 - OK
37 - OK
38 - NOISE - 1. Removed multiple functions from hci_conn.c - only changed the error semantics but do not introduce any validation to address the vulnerability; 
             2. Removed multiple functions from hci_event.c - the fix for multiple functions addressed the same exact problem (parameter value validation); in addtion there were alswo changes to error semantics which were not relevent
             3. All fixed in l2cap_core.c were also done in other files - were all noise
39 - OK
41 - OK
42 - NOISE - Removed cahnges to MakeFile (a file was created in the fix and it was simply added to the makefile)
43 - NOISE - Same exact fix in two files
44 - NOISE - multiple fix repeat in two function in file af_unix.c and garbage.c
     MISSING CODE - only part of the struct included in file scm.h
45 - MISSING CODE - Added multiple function to pipe.c - NEED TO CHECK REST WITH ARASTOO (nos ultimos, aquilo que la esta por si so nao e nenhuma vulnerabilidade... e suposto introduzir no dataset?)
46 - OK
48 - MISSING CODE - missing multiple functions and one struct
49 - OK
51 - OK
52 - OK
53 - OK
55 - MISSING CODE - Missing function v3d_cpu_job_free in .../v3d_sched.c
     NOISE - Same changes were made to all three functions in file .../ 3d_submit.c - kept only the first (v3d_get_cpu_timestamp_query_params)
56 - OK
57 - OK
58 - OK
59 - OK
60 - OK
61 - OK
62 - MISSING CODE - Only included part of the __mctp_key_remove and __mctp_key_done_in functions
63 - OK
64 - OK
65 - REMOVED - HAD SAME CVE AS 64 BUT THE COMMIT HASH IN NIST IS THE ONE IN 64
66 - OK
67 - OK
68 - OK
69 - NOISE - Same exact changes in functions ljca_enumerate_spi and ljca_enumerate_i2c, kept only ljca_enumerate_i2c
70 - OK
71 - OK
72 - OK
73 - NOISE - Most changes in geh commit were not security related
74 - OK
75 - OK
76 - OK
77 - NOISE - Same exact changes in all functions in .../sch_ingress.c file, kept only the first function (ingress_init)
     MISSING CODE - only captured only line of the struct in tcx.h and missing one function
78 - NOISE - Removed Kconfig file - only dependenct changes that do not affect code vulnerability
     NOISE - __nf_tables_abort had the same changes as nf_tables_commit
79 - OK
81 - OK
82 - NOISE - Same change made on every file, kept just the first (.../bxt_rt298.c)
83 - REMOVED - Only makefile changes
84 - OK
88 - REMOVED - Only changes in a documentation yaml file
90 - OK
91 - NOISE - Removed changes to yaml file - not security related code changes
     NOISE - .../netlink.c - Removal of old references due to refactoring, not the core security fix
     NOISE - .../netlink.h - Removal of unused function prototypes after refactor, non-security.
92 - OK
93 - OK
94 - OK
95 - NOISE - Same exact change in both functions, kept only the first (copy_page_to_iter_pipe)
96 - OK
97 - OK
98 - MISSING CODE - Missing static int from the function declaration
99 - OK
100 - OK
101 - NOISE - Same exact change in both functions, kept only the first (add_slot_store)
102 - OK
103 - OK
104 - OK
105 - OK
106 - OK
107 - NOISE - Removed array_access.c changes (only an error string was changed)
109 - NOISE - Function __inet_hash_connect has duplicated in the patched code - removed duplicate
110 - OK
111 - NOISE - Removed changes to file ip-sysctl.rst as they are only documentation changes
112 - NOISE - random32.c - included too many lines
113 - NOISE - skbuff.h - included additional info
      MISSING CODE - flow_dissector.h - included only part of struct
      MISSING CODE - fq.h - included only part of struct
      MISSING CODE - multiple missing function in flow_dissector.c
      MISSING CODE - missing struct in sch_hhf.c
      MISSING CODE - sch_sfc.c - missing function sfb_init_perturbation
      NOISE - sch-sfc.c - include and struct same as preivous file
      NOISE - sch-sfq.c - include and struct same as preivous file
114 - NOISE - uaccess.h - related cleanup after the main functional changes - not directly a security fix
      MISSING CODE - uaccess_64.h - the function raw_copy_from_user was not correctly extracted
115 - NOISE - core.c - Refactoring only — removes unnecessary #ifdef since barrier_nospec() is now globally defined. No direct security impact.
116 - OK
117 - OK
118 - OK
119 - OK
120 - OK
121 - NOISE - bset.c - some functions had the exact same changes
      MISSING CODE - bset.c - missing structs in both vulnerable and patched code
      NOISE - bset.h - included functions not changed
      MISSING CODE - bset.h - missed struct changes and #define
      NOISE - btree.c - all functions had the same changes
      NOISE - writeback.c - all duplicate changes
122 - OK
123 - MISSING CODE - missing struct
124 - OK
125 - REMOVED - 36 files changed and nothing was included
126 - MISSING CODE - ice-lib.c - missing function ice_vsi_clear_napi_queues (patched code)
127 - NOISE _ tc_flower.sh - only changes in tests
128 - OK
129 - NOISE. - dasd.c - _dasd_sleep_on_queue suppression checks are structurally identical to dasd_int_handler
130 - OK
131 - OK
132 - OK
133 - OK
134 - OK
135 - REMOVED - only changes in assembly files
136 - OK
137 - OK
138 - MISSING CODE - xfrm_interface_core.c - Missing struct (both) and multiple functions (patched)
139 - OK
140 - NOISE - ice.rst - Only doc changes
      NOISE - ice.h - Included many things that were not changed
      NOISE - ice_dcb_lib.c - One function had duplicate changes
      NOISE - ice_dcb_lib.h - Included many things that were not changed
141 - NOISE - Included example of new validation rule (not a direct security fix)
142 - OK
143 - MISSING CODE - ip4_fib.h - missing struct
      NOISE - fib6_rules.c - included function that was not changed
      MISSING CODE - fib6_rules.c - missing function
144 - OK
145 - OK
146 - MISSING CODE - missing function prace_setoptions
147 - OK
148 - OK
149 - OK
150 - OK
151 - OK
152 - OK
153 - OK
154 - OK
155 - OK
156 - OK
157 - OK
158 - OK
159 - NOISE - both functions had the same changes, kept the first
160 - MISSING CODE - function nci_rx_work was missing in both vulnerable and patched code
161 - OK
162 - OK
163 - OK
165 - OK
166 - OK
167 - OK
168 - MISSING CODE - function declaration cut in half for both vuln and patched code
170 - REMOVED - no important changes in this commit
172 - NOISE - Same fix for all functions, kept just the first as representative example
173 - MISSING CODE - ip_set.h - missing structs in both vuln and patched code
      MISSING CODE - ip_set_bitmap_gen.h - missing struct
      NOISE - ip_set_hash_gen.h - added function is a duplicate and functio/struct changes are duplicates
      NOISE - ip_set_list_set.h - added function is a duplicate and function/struct changes are duplicates
174 - OK
175 - NOISE - all changes in llcp_commands.c are duplicate
176 - OK
177 - OK
178 - OK
179 - OK
180 - MISSING CODE - missing two functions in both vuln and patched code
181 - MISSING CODE - missing function in both vuln and patched code
182 - OK
183 - NOISE - most files had the same duplicate changes
184 - REMOVED - only contained test changes
185 - OK
186 - NOISE - one file contained duplicate changes
      MISSING CODE - struct missing
187 - OK
188 - OK
189 - OK
190 - MISSING CODE - missing structs in multiple files
      NOISE - One file had no security patches
191 - NOISE - Changes were duplicate
192 - OK
193 - OK
194 - MISSING CODE - missing one function in vuln code
195 - REMOVED - no important patch
196 - OK
197 - REMOVED - no changed C code (only assembly)
198 - MISSING CODE - missing struct in vuln and patched code
199 - MISSING CODE - missing some of the added functions
200 - OK
201 - OK
202 - OK
203 - OK
204 - OK
205 - OK
206 - REMOVED - changes only make sense when considering the entire repo
207 - NOISE - most functions had the same changes
      MISSING CODE - some functions and structs were missing
208 - OK
209 - REMOVED - all changes in here are the same as done in 207 (converting filesystem from a global cache to per-fs one) the only difference is that it is done in different files
211 - REMOVED - only documentation changes
212 - NOISE - same exact change in all functions -> kept first as representative
213 - OK
214 - NOISE - multiple duplicate changes across many files
215 - OK
216 - OK
217 - MISSING CODE - some functions and structs missing
      NOISE - some duplicate function changes
218 - OK

# Leakage Free:

1 - Wrong Hash
2 - Wrong Hash
3 - Wrong Hash
4 - Wrong Hash
5 - Wrong Hash
6 - Wrong Hash
7 - Wrong Hash
8 - OK
9 - Wrong Hash
10 - Wrong Hash
11 - Wrong Hash
12 - Wrong Hash
13 - Wrong Hash
14 - Wrong Hash
15 - Wrong Hash
16 - Wrong Hash
17 - Wrong Hash
18 - REMOVED - CVE does not appear on NVD - "This CVE has been marked Rejected in the CVE List. These CVEs are stored in the NVD, but do not show up in search results by default."
19 - Wrong Hash
20 - Wrong Hash
21 - Wrong Hash
22 - Wrong Hash
23 - Wrong Hash
24 - Wrong Hash
25 - Wrong Hash
26 - Wrong Hash
27 - REMOVED - Not from 2025
28 - Wrong Hash
29 - Wrong Hash
30 - Wrong Hash
31 - Wrong Hash
32 - Wrong Hash
33 - Wrong Hash
34 - Wrong Hash
35 - Wrong Hash
36 - OK
37 - Wrong Hash
38 - Wrong Hash
39 - Wrong Hash
40 - Wrong Hash
41 - REMOVED - No commit hash from torvalds/linux/kernel repo 
42 - Wrong Hash
43 - OK
44 - Wrong Hash
45 - REMOVED - CVE did not exist
46 - Wrong Hash
47 - Wrong Hash
48 - Wrong Hash
49 - Duplicate CVE
50 - Wrong Hash
51 - Wrong Hash
52 - REMOVED - no useful information
53 - OK
54 - Wrong Hash
55 - Wrong Hash