@echo off
rem fake-tshark.cmd - test double for the SNI capture child. Emits tshark
rem "-T fields" TSV lines (ip.dst, ipv6.dst, tcp.dstport, sni[, http.host])
rem and exits, letting supervisor tests observe a dead child. Records its
rem argv to FAKE_TSHARK_ARGS when that env var is set (invocation asserts).
if defined FAKE_TSHARK_ARGS echo %* > "%FAKE_TSHARK_ARGS%"
echo 104.18.20.246			443	api.kimi.com
echo 	2606:4700::6812:14f6	443	v6.example.net
echo 104.18.21.213			80		yr1.c.lencr.org
