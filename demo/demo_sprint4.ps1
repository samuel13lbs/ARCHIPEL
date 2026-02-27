# Sprint 4 demo helper (PowerShell)
# Open three terminals and run one line per terminal.

# Terminal A
# $env:PYTHONPATH="src"; python -m cli.archipel start --port 7777

# Terminal B
# $env:PYTHONPATH="src"; python -m cli.archipel start --port 7778

# Terminal C
# $env:PYTHONPATH="src"; python -m cli.archipel start --port 7779

# Suggested jury flow:
# 1) On A: peers
# 2) On A: trust <prefix_of_B>
# 3) On B: trust <prefix_of_A>
# 4) On A: msg <prefix_of_B> "hello secure"
# 5) On A: send <prefix_of_B> "<path_to_50mb_file>"
# 6) On B: files
# 7) On B: download <file_id> <prefix_of_A>
# 8) On B: status
