#!/bin/sh
# Validate Tor's ntor implementation.

exitcode=0

"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/ntor_isogeny_ref.py" test-tor-demo || exitcode=1
"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/ntor_isogeny_ref.py" test-tor-sidh || exitcode=1
"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/ntor_isogeny_ref.py" test-tor-sike || exitcode=1


exit ${exitcode}
