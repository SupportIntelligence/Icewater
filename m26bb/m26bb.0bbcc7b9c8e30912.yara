
rule m26bb_0bbcc7b9c8e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.0bbcc7b9c8e30912"
     cluster="m26bb.0bbcc7b9c8e30912"
     cluster_size="1863"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hfsadware igeneric mailru"
     md5_hashes="['52c855addb788f3410700be7a33da576af615f86','148eedc9a80e7248be8f7ff545513c16c8ca5949','1490bc12945968db9ceaee110d805b53589f18c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.0bbcc7b9c8e30912"

   strings:
      $hex_string = { c0890aeb036a09588b4dfc5f5e33cd5be8a54a00008be55dc3558bec51518b55088a0288450b3c2d750142f20f101dd8c741000f57c98a0a8ac12c303c097719 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
