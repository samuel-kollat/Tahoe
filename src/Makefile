#------------------------------------------------------------------
# Makefile - Make rules for ONE-P Sample applications
#
# Copyright (c) 2011-2012 by cisco Systems, Inc.
# All rights reserved.
#------------------------------------------------------------------
include Makefile.defs

# Objects file to build
OBJSNETAPP += \
	obj/tahoe.o \
	obj/tahoe_util.o \
	obj/db_wrapper.o \
	obj/db_mysql.o \
	obj/action.o \
	obj/policy_map.o \
	obj/class_map.o \
	obj/acl.o \
	obj/router.o \
	obj/print.o \
	obj/api.o \
	obj/config.o \
	obj/configuration.o \
	obj/connector.o \
	obj/callback.o \
	obj/modules.o \
	obj/parsers.o \
	obj/queues.o \
	obj/pcap.o \
	obj/dns.o \
	obj/dns_resolutions.o

LD_LIBS += -lonep${ONEP_LBITS}_datapath

# All Target
# To build DatapathTutorial: "make bin/DatapathTutorial"
all: makedirs bin/tahoe

# Add inputs and outputs from these tool invocations to the build variables

makedirs:
	@if [ ! -d obj ] ; then mkdir obj ; fi
	@if [ ! -d bin ] ; then mkdir bin ; fi

makeutil:
	${MAKE} -C SessionElement all

# Tool invocations
bin/tahoe: makedirs makeutil $(OBJSNETAPP)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -o $@ $(OBJSNETAPP) \
			SessionElement/obj/session_element_util.o \
			$(LD_FLAGS) $(LD_LIBDIRS) $(LD_LIBS) -lpcap `mysql_config --cflags --libs`
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) -rf obj bin
	-@echo ' '

obj/db_mysql.o: database/mysql/db_mysql.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<" `mysql_config --cflags --libs`
	@echo 'Finished building: $<'
	@echo ' '

obj/db_wrapper.o: database/db_wrapper.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<" `mysql_config --cflags --libs`
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: queues/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: filtering/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/modules/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/protocols/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -lpcap -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/modules/print/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/modules/pcap/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -lpcap -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: processing/modules/dns/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -lpcap -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

obj/%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<" `mysql_config --cflags --libs`
	@echo 'Finished building: $<'
	@echo ' '

.PHONY: all clean dependents
.SECONDARY:

