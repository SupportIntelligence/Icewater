
rule k26c0_614fa48dc4010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.614fa48dc4010b32"
     cluster="k26c0.614fa48dc4010b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeav malicious heuristic"
     md5_hashes="['114e4e93023af09398358ec28ea37475d15edad1','6257d6c85e885823167aa98d2d87660af8a12504','d6b999e7dc80834b09a6def87f9c742c095cbb8e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.614fa48dc4010b32"

   strings:
      $hex_string = { 0000254b734b274d744d26488d4828509150214984492251765124477747234f754f2d5292522e5393536b4e904e6d4a8e4a7a8585857b868686bd0c0c82bb0d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
