<?php
//
// ABNF to REGEX example form.
//
// Copyright (c) 2013-2017 Michael R Sweet
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

print("<!doctype html>\n"
     ."<html>\n"
     ."  <head>\n"
     ."    <title>ABNF-REGEX Generator</title>"
     ."  </head>\n"
     ."  <body>\n"
     ."    <h1>ABNF-REGEX Generator</h1>\n");

$abnf_text = "";
$abnf_rule = "";
$abnf_mode = ABNF_INSENSITIVE;

if ($REQUEST_METHOD == "POST")
{
  if ($abnf_text == "" && array_key_exists("abnf_text", $_POST))
    $abnf_text = trim($_POST["abnf_text"]);

  if (array_key_exists("abnf_rule", $_POST))
    $abnf_rule = trim($_POST["abnf_rule"]);

  if (array_key_exists("abnf_mode", $_POST))
    $abnf_mode = (int)$_POST["abnf_mode"];
}

if (($rules = abnf_load($abnf_text)) === FALSE)
{
  print("    <pre>Error in ABNF:\n\n");

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
           ."<b>^ $abnf_error</b>\n\n");
  }
  print("</pre>\n");
}
else if ($abnf_rule != "")
{
  $html  = htmlspecialchars($abnf_rule);
  $regex = str_replace(array("(", "|"), array("<wbr>(", "|<wbr>"),
                       htmlspecialchars(abnf_regex($rules, $abnf_rule,
                                                   $abnf_mode)));
  print("    <blockquote><tt>$html: ^$regex\$</tt></blockquote>\n");
}

print("    <form method=\"POST\">\n"
     ."    <p>ABNF Text:<br>\n"
     ."    <textarea name=\"abnf_text\">" . htmlspecialchars($abnf_text) . "</textarea></p>\n");

if ($rules !== FALSE && sizeof($rules) > 0)
{
  // Show list of rules that can be generated...
  $list = array();
  foreach ($rules as $name => $value)
    $list[$name] = $name;
  ksort($list);

  print("    <p>ABNF Rule: <select name=\"abnf_rule\"><option value=\"\">-- Choose a Rule --</option>");
  foreach ($list as $name)
  {
    if ($name == $abnf_rule)
      print("<option selected>" . htmlspecialchars($name) . "</option>");
    else
      print("<option>" . htmlspecialchars($name) . "</option>");
  }
  print("</select></p>\n");

  // Show regular expression modes...
  $modes = array("Case-Insensitive", "Case-Sensitive", "Lowercase", "Uppercase");

  print("    <p>REGEX Mode: <select name=\"abnf_mode\"><option value=\"\">-- Choose a Rule --</option>");
  for ($i = 0; $i < sizeof($modes); $i ++)
  {
    if ($i == $abnf_mode)
      print("<option value=\"$1\" selected>$modes[$i]</option>");
    else
      print("<option value=\"$1\">$modes[$i]</option>");
  }
  print("</select></p>\n");

  print("    <p><input type=\"SUBMIT\" value=\"Generate REGEX\"></p>\n");
}
else
  print("    <p><input type=\"SUBMIT\" value=\"Choose Rule\"></p>\n");

print("    </form>\n"
     ."  </body>\n"
     ."</html>\n");
?>
