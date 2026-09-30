# Windows host detection module: os. Owned by ahliweb/linux-mint-xfce-rescue-ai#16.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
# Contract (docs/repair-framework.md): run by host/rescue-windows.ps1 with the call operator in a
# child scope. Read-only, no elevation. Emit one hashtable per check:
#   @{ check_id = 'hw-cpu'; status = 'pass' }   or   @{ check_id = '...'; status = 'warn'; kind = 'count'; number = 3 }
# check_id must be in rescue-ai/v1/rescue-evidence.schema.json; anything else is dropped.
param([string[]]$Scope = @('all'), [string[]]$Packages = @())
