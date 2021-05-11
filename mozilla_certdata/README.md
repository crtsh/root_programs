mozilla_certdata
================

Introduction
------------

This application provides Mozilla's root certificate store information to crt.sh. It parses the [certdata.txt](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt) file from Mozilla's source code management system. This file contains Mozilla's root certificate store in a form that is convenient for Mozilla's [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) library to build from. Each root certificate in certdata.txt has metadata associated with it; briefly, this can include:
  * Trust records, labelled CKA_TRUST_SERVER_AUTH and CKA_TRUST_EMAIL_PROTECTION, which indicate the purposes (TLS and/or S/MIME) that Mozilla has determined the root certificate to be trustworthy for.
  * Distrust records, labelled CKA_NSS_SERVER_DISTRUST_AFTER and CKA_NSS_EMAIL_DISTRUST_AFTER, which allow Mozilla to distrust leaf certificates issued after a certain date (that chain up to the root certificate) whilst continuing to trust older leaf certificates until they expire.
  * Explicit Distrust records, which look similar to Trust records but are accompanied by a CKT_NSS_NOT_TRUSTED attribute.

Many applications use Mozilla's root certificate store instead of curating their own root certificate store, but they don't always correctly consider the metadata for each root certificate. This can lead to root certificates being trusted for purposes for which their trustworthiness has not been assessed, or for which they are no longer deemed trustworthy.

Note that [Mozilla now recommends](https://blog.mozilla.org/security/2021/05/10/beware-of-applications-misusing-root-stores/) that application developers use the certificate lists provided on the [CCADB Resources page](https://www.ccadb.org/resources) instead of parsing certdata.txt directly.

Building
--------

``` bash
go build
```

Usage
-----

``` bash
wget https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
./mozilla_certdata certdata.txt > mozilla_certdata.sql
```

mozilla_certdata.sql can then be executed on the crt.sh master database.

Acknowledgements
----------------

mozilla_certdata.go was originally forked from Adam Langley's [extract-nss-root-certs](https://github.com/agl/extract-nss-root-certs) repository, which (as of 10th May 2021) does not support the CKA_NSS_SERVER_DISTRUST_AFTER and CKA_NSS_EMAIL_DISTRUST_AFTER Distrust record types.
