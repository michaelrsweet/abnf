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

if ($argc < 2 || $argc > 3)
{
  print("Usage: ./testabnf.php filename.abnf [rulename]\n");
  exit(1);
}

$abnf_file = $argv[1];
$abnf_rule = $argv[2];
$abnf_text = trim(file_get_contents($abnf_file));
$abnf_mode = ABNF_INSENSITIVE;

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
