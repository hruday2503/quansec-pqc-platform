AM_CPPFLAGS = -I$(top_srcdir)/src/libstrongswan -I/usr/local/include
AM_CFLAGS   = $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ml-kem.la
else
plugin_LTLIBRARIES = libstrongswan-ml-kem.la
endif

libstrongswan_ml_kem_la_SOURCES  = ml_kem_plugin.c ml_kem_plugin.h ml_kem_ke.c ml_kem_ke.h
libstrongswan_ml_kem_la_LIBADD   = -L/usr/local/lib -loqs
libstrongswan_ml_kem_la_LDFLAGS  = -module -avoid-version
