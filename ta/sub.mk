global-incdirs-y += include

srcs-y += onLinePayTaEntry.c
srcs-y += onLinePayTaHandle.c
srcs-y += onLinePayTaAes.c
srcs-y += onLinePayTaHash.c
srcs-y += onLinePayTaPbkdf2.c
srcs-y += onLinePayTaDebug.c
srcs-y += onLinePayTaOther.c
srcs-y += onLinePayTaRsa.c



# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
