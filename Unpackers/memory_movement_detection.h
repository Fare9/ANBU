#pragma once

#ifndef MEMORY_MOVEMENT_DETECTION_H
#define MEMORY_MOVEMENT_DETECTION_H

#include "common.h"
#include "generic_instrumentation.h"
#include "w_xor_x_heuristic.h"
#include "pushad_popad_heuristic.h"

// PE Headers
#include "binary.h"



/******************* unpacker funcionts *******************/
void fini();

void instrument_mem_cflow(INS ins, void *v);
void queue_memwrite(ADDRINT addr);
void log_memwrite(UINT32 size);
void check_indirect_ctransfer(ADDRINT ip, ADDRINT target, BOOL taken);
bool dump_to_file(ADDRINT target);

#endif // !MEMORY_MOVEMENT_DETECTION_H
