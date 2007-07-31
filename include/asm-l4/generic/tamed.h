#ifndef __ASM_L4__GENERIC__TAMED_H__
#define __ASM_L4__GENERIC__TAMED_H__

void l4x_tamed_init(int nr);
void l4x_tamed_set_mapping(int cpu, int nr);
int  l4x_tamed_print_cli_stats(char *buffer);

#endif /* ! __ASM_L4__GENERIC__TAMED_H__ */
