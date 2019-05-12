#include "pushad_popad_heuristic.h"

/************* EXTERN VARIABLES *************/
extern FILE*								logfile;			// log file handler

pushad_popad_heuristic_t::pushad_popad_heuristic_t() : pushad_flag(false),
													   popad_flag(false)
{
}

void pushad_popad_heuristic_t::check_pushad_popad(INS instruction)
{
	std::string ins = INS_Disassemble(instruction);

	if (ins.compare("pushad ") == 0)
	{
		fprintf(stderr, "[INFO] Pushad detected\n");
		fprintf(logfile, "[INFO] Pushad detected\n");
		this->pushad_flag = true;
	}
	else if (ins.compare("popad ") == 0)
	{
		fprintf(stderr, "[INFO] Popad detected\n");
		fprintf(logfile, "[INFO] Popad detected\n");
		this->popad_flag = true;
	}
}

bool pushad_popad_heuristic_t::pushad_popad_detected()
{
	return this->pushad_flag;
}

bool pushad_popad_heuristic_t::pushad_popad_finished()
{
	return (this->pushad_flag && this->popad_flag);
}
