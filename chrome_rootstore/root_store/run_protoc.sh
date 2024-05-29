#!/bin/bash
protoc --go_opt=Mroot_store.proto=. --go_out=. root_store.proto
