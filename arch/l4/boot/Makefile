#
# arch/l4/boot/Makefile
#

SUFFIX = $(patsubst "%",%,$(CONFIG_L4_VMLINUZ_SUFFIX))

targets := vmlinuz$(SUFFIX)

quiet_cmd_compr = COMPR   $< to $@
      cmd_compr = gzip -9c $< > $@

quiet_cmd_localinst = LOCINST $@
      cmd_localinst = ([ -x "$(srctree)/arch/l4/install.local" ] && \
                       $(srctree)/arch/l4/install.local $@ $(BASEARCH)) || true

Image: vmlinux FORCE
	$(call if_changed,objcopy)

vmlinuzimage: vmlinuz$(SUFFIX)

vmlinuz$(SUFFIX): Image FORCE
	$(call if_changed,compr)
	$(call cmd,localinst)

PHONY += vmlinuzimage
