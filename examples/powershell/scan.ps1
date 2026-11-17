# Copyright (c) 2026 hors<horsicq@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# xxyara example in PowerShell 7: compiles ..\csharp\Scan.cs with Add-Type and calls it.
# usage: pwsh scan.ps1 <rules.yar> <file> <path to xxyara.dll>
param(
    [Parameter(Mandatory = $true)][string]$Rules,
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][string]$Library
)
$ErrorActionPreference = 'Stop'
# Load the DLL by its full path first; P/Invoke of "xxyara" then binds to the loaded module.
[void][System.Runtime.InteropServices.NativeLibrary]::Load((Resolve-Path -LiteralPath $Library).Path)
Add-Type -Path (Join-Path $PSScriptRoot '..\csharp\Scan.cs')
$status = [XXYara.Example.Program]::Main(@((Resolve-Path -LiteralPath $Rules).Path, (Resolve-Path -LiteralPath $File).Path))
exit $status
