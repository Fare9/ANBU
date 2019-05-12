#pragma once

#ifndef PUSHAD_POPAD_HEURISTIC_H
#define PUSHAD_POPAD_HEURISTIC_H

#include "common.h"

class pushad_popad_heuristic_t
{
public:
	pushad_popad_heuristic_t();
	~pushad_popad_heuristic_t() = default;

	void check_pushad_popad(INS instruction);
	bool pushad_popad_detected();
	bool pushad_popad_finished();

private:
	bool pushad_flag = false;
	bool popad_flag = false;
};

#endif // !PUSHAD_POPAD_HEURISTIC_H
