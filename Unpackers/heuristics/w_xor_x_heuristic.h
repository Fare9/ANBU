#pragma once
#ifndef W_XOR_X_HEURISTIC_H
#define W_XOR_X_HEURISTIC_H

#include "common.h"


class w_xor_x_heuristic_t
{
public:
	/***
	 *  Structure to track memory activity
	 *  we will log written or executed bytes
	 *  from memory. For that reason
	 *  we record the type of memory access (write or execute)
	 *  and the value of written bytes
	 */
	typedef struct mem_access
	{
		mem_access() : w(false), x(false), val(0) {}
		mem_access(bool ww, bool xx, unsigned char v) : w(ww), x(xx), val(v) {}
		bool w;
		bool x;
		unsigned char val;
	} mem_access_t;

	/***
	 *  In the unpacking process, we will need to cluster
	 *  adjacent memory bytes to know which memory dump.
	 *  For that is this structure, we will record the
	 *  base address, the size and the access permission
	 */
	typedef struct mem_cluster
	{
		mem_cluster() : base(0), size(0), w(false), x(false) {}
		mem_cluster(ADDRINT b, unsigned long s, bool ww, bool xx)
			: base(b), size(s), w(ww), x(xx) {}
		ADDRINT         base;
		unsigned long   size;
		bool            w;
		bool            x;
	} mem_cluster_t;

	w_xor_x_heuristic_t()	= default;
	~w_xor_x_heuristic_t()	= default;

	void set_shadow_memory_as_writable(ADDRINT target);
	void set_shadow_memory_as_executable(ADDRINT target);
	void set_shadow_memory_value(ADDRINT target, unsigned char val);

	bool is_shadow_memory_writable(ADDRINT target);
	bool is_shadow_memory_executable(ADDRINT target);

	void set_cluster(ADDRINT target, bool dump);
	bool in_cluster(ADDRINT target);



private:

	void add_cluster_to_clusters_list(mem_cluster_t c);
	void dump_cluster_to_file(mem_cluster_t c, ADDRINT entry);

	std::map<ADDRINT, mem_access_t>				shadow_mem;			// map memory addresses with memory
																	// access permissions.
	std::vector<mem_cluster_t>					clusters;			// vector to store all the unpacked memory
																	// clusters found
};

#endif // !W_XOR_X_HEURISTIC_H
