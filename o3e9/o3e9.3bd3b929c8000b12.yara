
rule o3e9_3bd3b929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3bd3b929c8000b12"
     cluster="o3e9.3bd3b929c8000b12"
     cluster_size="23"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious qjwmonkey"
     md5_hashes="['0520fbd28a99448f7cb2cb386364be6e','130c0457a641de479d88fc122b8d6855','c8e18aaffaaec0e0d6fe0cdab86906ba']"

   strings:
      $hex_string = { fab893da1d79ec60dd42d8bbba4326b2a04dc702bd76210e9ab6d18c9db1835740e32e3c9bb56d44e19461cc718e5c5054a41cf716fee311d6660f7ab32fa263 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
