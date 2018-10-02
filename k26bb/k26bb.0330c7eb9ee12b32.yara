
rule k26bb_0330c7eb9ee12b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.0330c7eb9ee12b32"
     cluster="k26bb.0330c7eb9ee12b32"
     cluster_size="47"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unwanted widgi creprote"
     md5_hashes="['025e77b908baff93ab425b6d9d6076d9557ae96b','265260f3437881cee9e4a76478a1cc371311b2e1','ddcd76583895649893bf7627747a30108741ba37']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.0330c7eb9ee12b32"

   strings:
      $hex_string = { fff01b4a48538f75fae5f1a115013ee7f26da8a40f21d60563b50e3ab47a59b176e2aadd9347f7027449112dd5786c186e5eeef6a24385002355910d56de0358 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
