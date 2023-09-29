#!/bin/bash
echo "DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 26;"
curl -s "https://support.google.com/a/answer/7448393?hl=en" | grep -oP "(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}" | tr -d ':' | sed "s/^/INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT c.ID, 26, 3 FROM certificate c WHERE digest(c.CERTIFICATE, 'sha256') = E'\\\\\\\\x/g" | sed "s/$/';/g"
