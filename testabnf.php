#!/usr/bin/php -f
<?php
//
// ABNF to REGEX unit test program.
//
// Usage:
//
//   ./testabnf.php filename.abnf [rulename]
//
// Copyright (c) 2019 Michael R Sweet
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
//

include_once "abnf-functions.php";

global $_SERVER;
$argc = $_SERVER["argc"];
$argv = $_SERVER["argv"];

$abnf_file = "";
$abnf_rule = "";
$abnf_mode = ABNF_INSENSITIVE;

for ($i = 1; $i < $argc; $i ++)
{
  if ($argv[$i] == "-l")
    $abnf_mode = ABNF_LOWERCASE;
  else if ($argv[$i] == "-s")
    $abnf_mode = ABNF_SENSITIVE;
  else if ($argv[$i] == "-u")
    $abnf_mode = ABNF_UPPERCASE;
  else if ($argv[$i][0] == '-')
  {
    $opt = $argv[$i];
    print("Unknown option '$opt'.\n");
    break;
  }
  else if ($abnf_file == "")
    $abnf_file = $argv[$i];
  else if ($abnf_rule == "")
    $abnf_rule = $argv[$i];
  else
    break;
}

if ($abnf_file == "" || $i < $argc)
{
  print("Usage: ./testabnf.php [options] filename.abnf [rulename]\n");
  print("Options:\n");
  print("  -l   Lowercase ABNF\n");
  print("  -s   Case-sensitive ABNF as specified\n");
  print("  -u   Uppercase ABNF\n");
  exit(1);
}

$abnf_text = trim(file_get_contents($abnf_file));

if (($rules = abnf_load($abnf_text)) === FALSE)
{
  print("Error in ABNF:\n\n");

  $temp = explode("\n", $abnf_text);

  $start = $abnf_errorline - 4;
  if ($start < 0)
    $start = 0;

  $end = $abnf_errorline + 3;
  if ($end > sizeof($temp))
    $end = sizeof($temp);

  for ($i = $start; $i < $end; $i ++)
  {
    printf("%4d  %s\n", $i + 1, htmlspecialchars($temp[$i]));
    if (($i + 1) == $abnf_errorline)
      print("      " . str_repeat(" ", $abnf_errorcol)
           ."^ $abnf_error\n\n");
  }

  exit(1);
}

if ($abnf_rule != "")
{
  // Show regular expression for specified rule...
  print(abnf_regex($rules, $abnf_rule, $abnf_mode) . "\n");
}
else
{
  // Show list of rules that can be generated...
  $list = array();
  foreach ($rules as $name => $value)
    $list[$name] = $name;
  ksort($list);

  foreach ($list as $name)
    print("$name\n");
}
?>
