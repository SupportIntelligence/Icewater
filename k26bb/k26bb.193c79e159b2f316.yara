
rule k26bb_193c79e159b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193c79e159b2f316"
     cluster="k26bb.193c79e159b2f316"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['a34fed97beaaf91b6db7e0006aa962467bd13d87','bd27e568210b3243d0314e47ce7eaf23c96a6b60','1422b6ccb81f3dc027f4b09c3a69c32a19cbea55']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193c79e159b2f316"

   strings:
      $hex_string = { 6120697320636f72727570746564202825642900005383c4f88bd8891c24c64424040b546a00b9187e4000b201b8c8774000e8bedaffffe8a9b0ffff595a5bc3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
