
rule k26bb_193e79e351b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193e79e351b2f316"
     cluster="k26bb.193e79e351b2f316"
     cluster_size="295"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore unwanted dealply"
     md5_hashes="['65cd13ab8d937ab5543c48f19805983af88a5e17','2f61396d7daf422ba97a191c30bff9aa40dbeea9','50cda02ab2ef74503a6458633f5d9279a31e414a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193e79e351b2f316"

   strings:
      $hex_string = { 6120697320636f72727570746564202825642900005383c4f88bd8891c24c64424040b546a00b9187e4000b201b8c8774000e8bedaffffe8a9b0ffff595a5bc3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
