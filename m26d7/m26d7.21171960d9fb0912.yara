
rule m26d7_21171960d9fb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.21171960d9fb0912"
     cluster="m26d7.21171960d9fb0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['36a0567c84fe463faec888a63c7796c7adf4845f','7be8eab55b8998ad0d8be91afd13cfd0b74b1b75','303f59eeb8488c259a1ec0636c45574e579bea8b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.21171960d9fb0912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
