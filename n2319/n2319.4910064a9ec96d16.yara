
rule n2319_4910064a9ec96d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4910064a9ec96d16"
     cluster="n2319.4910064a9ec96d16"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['68e7d80c868234065adb65f122c3ad5fa6817724','394de3aa351a88b3d94124409798cd2f0b299574','fdbfd7bf39933c25235a6d52edbc26f64abbd729']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4910064a9ec96d16"

   strings:
      $hex_string = { 2f55492d5472616e736974696f6e3e227d2c7265674578703a7b6573636170653a2f5b2d5b5c5d7b7d28292a2b3f2e2c5c5c5e247c235c735d2f672c71756f74 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
