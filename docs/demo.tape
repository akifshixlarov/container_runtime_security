# VHS Tape: Kubernetes Runtime Security Lab Demo
# To generate docs/demo.gif, install VHS (https://github.com/charmbracelet/vhs) and run:
#   vhs docs/demo.tape

Output docs/demo.gif

Set FontSize 16
Set Width 1200
Set Height 680
Set Padding 20
Set Theme "Catppuccin Mocha"

Type "# 1. Inspecting production Nginx pod in 'prod' namespace"
Enter
Sleep 1s

Type "kubectl get pods -n prod -l app=nginx"
Enter
Sleep 2s

Type "# 2. Attempting interactive shell injection (/bin/sh) into production..."
Enter
Sleep 1s

Type "kubectl exec -n prod $(kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}') -- /bin/sh"
Enter
Sleep 2.5s

Type "# Tetragon in-kernel eBPF hook (sys_execve) intercepted the call and sent SIGKILL (exit code 137)!"
Enter
Sleep 2s

Type "# 3. Executing automated runtime security validation suite"
Enter
Sleep 1s

Type "./tests/run-runtime-security-tests.sh"
Enter
Sleep 7s
