#include "utils.h"

namespace LIEF {
	uint64_t align(uint64_t value, uint64_t align_on) 
	{
		if ((align_on > 0) && (value % align_on) > 0) {
			return  value + (align_on - (value % align_on));
		}
		else {
			return value;
		}
	}
}