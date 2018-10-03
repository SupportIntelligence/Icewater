
rule o26d5_490dea49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.490dea49c0000b32"
     cluster="o26d5.490dea49c0000b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['12c239ecd7b5a61445ad909b975f65fd29ff74b9','05e6d7c17f0cad4e8769ab38e2e870217aeb8be4','1d1490ecf2fd2c34a63d7ca442e4ea1691234694']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.490dea49c0000b32"

   strings:
      $hex_string = { 032905461bb26c8ac1b1019450a8a44110b90d549e4df18300cf0bd0454e610c51ad4918d7f04267f49a8efb04718de1ce06322fab20e2eff23560dc9823692c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
