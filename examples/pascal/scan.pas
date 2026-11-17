// Copyright (c) 2026 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

{ xxyara example in Pascal (Free Pascal, Delphi): the YARA-X C API of xxyara.dll / libxxyara.so.
  Free Pascal, 64-bit Windows: fpc -Px86_64 -Twin64 scan.pas
  usage: scan <rules.yar> <file> }
program scan;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$APPTYPE CONSOLE}

uses
  SysUtils, Classes;

const
{$IFDEF MSWINDOWS}
  XXYaraLibrary = 'xxyara.dll';
{$ELSE}
  XXYaraLibrary = 'libxxyara.so';
{$ENDIF}

type
  PYrxMatch = ^TYrxMatch;
  TYrxMatch = record
    Offset: NativeUInt;
    Length: NativeUInt;
    XorKey: SmallInt;
  end;
  TRuleCallback = procedure(Rule: Pointer; UserData: Pointer); cdecl;
  TPatternCallback = procedure(Pattern: Pointer; UserData: Pointer); cdecl;
  TMatchCallback = procedure(Match: PYrxMatch; UserData: Pointer); cdecl;

function yrx_compile(Source: PAnsiChar; out Rules: Pointer): Integer; cdecl; external XXYaraLibrary;
procedure yrx_rules_destroy(Rules: Pointer); cdecl; external XXYaraLibrary;
function yrx_scanner_create(Rules: Pointer; out Scanner: Pointer): Integer; cdecl; external XXYaraLibrary;
procedure yrx_scanner_destroy(Scanner: Pointer); cdecl; external XXYaraLibrary;
function yrx_scanner_on_matching_rule(Scanner: Pointer; Callback: TRuleCallback;
  UserData: Pointer): Integer; cdecl; external XXYaraLibrary;
function yrx_scanner_scan_file(Scanner: Pointer; Path: PAnsiChar): Integer; cdecl; external XXYaraLibrary;
function yrx_rule_identifier(Rule: Pointer; out Text: PAnsiChar; out Len: NativeUInt): Integer; cdecl;
  external XXYaraLibrary;
function yrx_rule_iter_patterns(Rule: Pointer; Callback: TPatternCallback;
  UserData: Pointer): Integer; cdecl; external XXYaraLibrary;
function yrx_pattern_identifier(Pattern: Pointer; out Text: PAnsiChar; out Len: NativeUInt): Integer; cdecl;
  external XXYaraLibrary;
function yrx_pattern_iter_matches(Pattern: Pointer; Callback: TMatchCallback;
  UserData: Pointer): Integer; cdecl; external XXYaraLibrary;
function yrx_last_error: PAnsiChar; cdecl; external XXYaraLibrary;

var
  CurrentPattern: AnsiString;

function MakeString(Text: PAnsiChar; Len: NativeUInt): AnsiString;
begin
  SetString(Result, Text, Len);
end;

function ReadText(const Path: string): AnsiString;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(Path, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, Stream.Size);
    if Stream.Size > 0 then
      Stream.ReadBuffer(Result[1], Stream.Size);
  finally
    Stream.Free;
  end;
end;

procedure OnMatch(Match: PYrxMatch; UserData: Pointer); cdecl;
begin
  WriteLn('  ', CurrentPattern, ' at ', Match^.Offset, ', ', Match^.Length, ' bytes');
end;

procedure OnPattern(Pattern: Pointer; UserData: Pointer); cdecl;
var
  Text: PAnsiChar;
  Len: NativeUInt;
begin
  if yrx_pattern_identifier(Pattern, Text, Len) <> 0 then
    Exit;
  CurrentPattern := MakeString(Text, Len);
  yrx_pattern_iter_matches(Pattern, @OnMatch, nil);
end;

procedure OnRule(Rule: Pointer; UserData: Pointer); cdecl;
var
  Text: PAnsiChar;
  Len: NativeUInt;
begin
  if yrx_rule_identifier(Rule, Text, Len) <> 0 then
    Exit;
  WriteLn(MakeString(Text, Len));
  yrx_rule_iter_patterns(Rule, @OnPattern, nil);
end;

var
  Source, Path: AnsiString;
  Rules, Scanner: Pointer;
  Status: Integer;
begin
  if ParamCount <> 2 then
  begin
    WriteLn(ErrOutput, 'usage: scan <rules.yar> <file>');
    Halt(2);
  end;
  Source := ReadText(ParamStr(1));
  if yrx_compile(PAnsiChar(Source), Rules) <> 0 then
  begin
    WriteLn(ErrOutput, yrx_last_error);
    Halt(1);
  end;
  Status := 1;
  if yrx_scanner_create(Rules, Scanner) = 0 then
  begin
    yrx_scanner_on_matching_rule(Scanner, @OnRule, nil);
    Path := UTF8Encode(ParamStr(2));
    if yrx_scanner_scan_file(Scanner, PAnsiChar(Path)) = 0 then
      Status := 0
    else
      WriteLn(ErrOutput, yrx_last_error);
    yrx_scanner_destroy(Scanner);
  end
  else
    WriteLn(ErrOutput, yrx_last_error);
  yrx_rules_destroy(Rules);
  Halt(Status);
end.
