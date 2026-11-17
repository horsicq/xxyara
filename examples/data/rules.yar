rule hello_world : greeting {
  meta:
    description = "a greeting"
  strings:
    $hello = "hello"
    $world = /w[o0]rld/
  condition:
    $hello and $world
}

rule not_there {
  strings:
    $a = "absent"
  condition:
    $a
}
