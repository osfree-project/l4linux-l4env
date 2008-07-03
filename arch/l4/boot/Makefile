#
# arch/l4/boot/Makefile
#

SUFFIX = $(patsubst "%",%,$(CONFIG_L4_VMLINUZ_SUFFIX))

targets := vmlinuz$(SUFFIX)

quiet_cmd_localinst = LOCINST $@
      cmd_localinst = ([ -x "$(srctree)/arch/l4/install.local" ] && \
                       $(srctree)/arch/l4/install.local $@ $(BASEARCH)) || true

Image: vmlinux FORCE
	$(call if_changed,objcopy)

lImage: Image vmlinuz$(SUFFIX)

vmlinuz$(SUFFIX): $(if $(CONFIG_L4_LDR),ldr)Image FORCE
	$(call if_changed,gzip)
	$(call cmd,localinst)

objects-$(CONFIG_L4_LDR) := ldr.o startup.o res.o

targets	:= $(objects-y)

KBUILD_CFLAGS	:= -m32 $(L4INC) -I$(L4OBJ)/include/uclibc \
		   -Wall -fno-strict-aliasing -O2 -pipe \
		   -DARCH_$(L4_MK_ARCH) \
		   -DVMLINUX_IMAGE=\"Image\" \
		   -I$(obj)

$(obj)/ldr.o: Image
$(obj)/res.o: $(obj)/func_list.h

$(obj)/func_list.h: vmlinux
	$(Q)objcopy -j .data.l4externals.str -O binary $< $@.tmp
	$(Q)perl -p -e 's/(.+?)\0/EF($$1)\n/g' $@.tmp > $@

OBJS := $(addprefix $(obj)/,$(objects-y))

$(obj)/ldr.ld: $(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU)/main_dyn.ld
	$(Q)sed -e 's/0x08048000/0x88048000/' < $< > $@

ldrImage: $(obj)/ldr.ld $(OBJS)
	@echo "  LD      $@"
	$(Q)$(LD) -o $@ \
	  $(OBJS) $(L4_DYNLINK) $(L4LIBS_PATH) \
	  --start-group $(L4LIBS-y) -luc_c --end-group \
	  -T$(obj)/ldr.ld

PHONY += lImage
