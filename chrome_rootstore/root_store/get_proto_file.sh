#!/bin/bash
wget -O root_store.proto.base64 "https://chromium.googlesource.com/chromium/src/+/main/net/cert/root_store.proto?format=TEXT"
base64 -d root_store.proto.base64 > root_store.proto
rm root_store.proto.base64
