#include "w_xor_x_heuristic.h"

/************* EXTERN VARIABLES *************/
extern FILE* logfile;

void w_xor_x_heuristic_t::set_shadow_memory_as_writable(ADDRINT target)
{
	shadow_mem[target].w = true;
}


void w_xor_x_heuristic_t::set_shadow_memory_as_executable(ADDRINT target)
{
	shadow_mem[target].x = true;
}


void w_xor_x_heuristic_t::set_shadow_memory_value(ADDRINT target, unsigned char val)
{
	shadow_mem[target].val = val;
}


bool w_xor_x_heuristic_t::is_shadow_memory_writable(ADDRINT target)
{
	if (shadow_mem.find(target) != shadow_mem.end())
	{
		return shadow_mem[target].w;
	}
	return false;
}


bool w_xor_x_heuristic_t::is_shadow_memory_executable(ADDRINT target)
{
	if (shadow_mem.find(target) != shadow_mem.end())
	{
		return shadow_mem[target].x;
	}
	return false;
}


void w_xor_x_heuristic_t::set_cluster(ADDRINT target, bool dump)
{
	mem_cluster_t c;

	ADDRINT addr, base;
	unsigned long size;
	bool w, x;
	std::map<ADDRINT, mem_access_t>::iterator i, j;

	j = shadow_mem.find(target);
	assert(j != shadow_mem.end());

	base = target;
	w = false;
	x = false;

	for (i = j; ; i--)
	{
		addr = i->first;

		if (addr == base)
		{
			if (i->second.w)
				w = true;
			if (i->second.x)
				x = true;
			base--;
		}
		else
		{
			base++;
			break;
		}

		if (i == shadow_mem.begin())
		{
			base++;
			break;
		}
	}

	size = target - base;
	for (i = j; i != shadow_mem.end(); i++)
	{
		addr = i->first;
		if (addr == base + size)
		{
			if (i->second.w)
				w = true;
			if (i->second.x)
				x = true;
			size++;
		}
		else
		{
			break;
		}
	}

	c.base = base;
	c.size = size;
	c.w = w;
	c.x = x;

	this->add_cluster_to_clusters_list(c);

	if (dump)
		this->dump_cluster_to_file(c, target);
}


bool w_xor_x_heuristic_t::in_cluster(ADDRINT target)
/*
*   Function to check target address is inside of
*   any memory cluster.
*/
{
	mem_cluster_t *c;

	for (unsigned i = 0; i < clusters.size(); i++)
	{
		c = &clusters[i];

		if (c->base <= target &&
			target < c->base + c->size)
		{
			return true;
		}
	}

	return false;
}


void w_xor_x_heuristic_t::add_cluster_to_clusters_list(mem_cluster_t c)
{
	clusters.push_back(c);
}


void w_xor_x_heuristic_t::dump_cluster_to_file(mem_cluster_t c, ADDRINT entry)
{
	FILE *f;
	char buf[256];

	ANBU::LOGGER_INFO("Extracting unpacked region 0x%x %c%c entry 0x%x\n",
		(uintptr_t)c.base, c.w ? 'w' : '-', c.x ? 'x' : '-', (uintptr_t)entry);

	snprintf(buf, sizeof(buf), "unpacked.0x%x-0x%x_entry-0x%x",
		(uintptr_t)c.base, (uintptr_t)(c.base + c.size), (uintptr_t)entry);

	f = fopen(buf, "wb");
	if (!f)
	{
		ANBU::LOGGER_ERROR(logfile, "Failed to open file '%s' for writing\n", buf);
	}
	else
	{
		for (ADDRINT i = c.base; i < c.base + c.size; i++)
		{
			if (fwrite((const void*)&shadow_mem[i].val, 1, 1, f) != 1)
			{
				ANBU::LOGGER_ERROR(logfile, "Failed to write unpacked byte 0x%x to file '%s'\n", (unsigned int)i, buf);
			}
		}

		fclose(f);
	}
}