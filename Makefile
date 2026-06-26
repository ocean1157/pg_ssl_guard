EXTENSION = pg_ssl_guard
MODULE_big = pg_ssl_guard
OBJS = src/pg_ssl_guard.o

DATA = pg_ssl_guard--1.0.sql
DOCS = README.md

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
