# harness.tests.ps1 - self-test of the assertion helpers.
. "$PSScriptRoot\_assert.ps1"

Assert-True $true 'true is true'
Assert-False $false 'false is false'
Assert-Equal 'abc' 'abc' 'string equality'
Assert-Equal 42 42 'int equality'
Assert-Null $null 'null is null'
Assert-NotNull 'x' 'x is not null'
Assert-Throws { throw 'boom' } 'throwing block detected'

# Failing assertion must itself throw (caught here, so the file still passes).
$caught = $false
try { Assert-Equal 1 2 'must fail' } catch { $caught = $true }
Assert-True $caught 'Assert-Equal 1 2 throws'

# Test state root lifecycle.
$root = New-TestStateRoot
Assert-True (Test-Path $root) 'test state root created'
$base = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch')
Assert-True ($root -like (Join-Path $base 'test-*')) 'root under jail state dir'
Remove-TestStateRoot $root
Assert-False (Test-Path $root) 'test state root removed'
Assert-Throws { Remove-TestStateRoot $base } 'refuses non-test dir'

Complete-Tests
