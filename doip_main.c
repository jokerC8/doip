#include "doip_entity.h"

int main()
{
	doip_entity_t *doip_entity = doip_entity_alloc();

	doip_entity_start(doip_entity);

	return 0;
}
