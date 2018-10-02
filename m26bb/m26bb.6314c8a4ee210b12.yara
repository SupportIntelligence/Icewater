
rule m26bb_6314c8a4ee210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.6314c8a4ee210b12"
     cluster="m26bb.6314c8a4ee210b12"
     cluster_size="210"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="filerepmalware attribute exploit"
     md5_hashes="['1ca66ac8fe6778b41a3fbe623bb182817da8d3f5','579051c2a901dabcb2bde70d40950ac95a20287d','840a6824fc85f221c2d2471098a1530bc3d941db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.6314c8a4ee210b12"

   strings:
      $hex_string = { d58ffa9b949e3f184f8595a6a3414e0d57d27cd4da6ba2edebfb6c708b14f474c265361998f67b629381a90976fa509c230320028e151399829d31e0e62a0b69 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
