
rule j2321_1a3a7a5cd2bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.1a3a7a5cd2bb1912"
     cluster="j2321.1a3a7a5cd2bb1912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="spyeyes upatre generickd"
     md5_hashes="['10343b290b8bd2f2899e85d225ff54ab','25155e543c052ea7ecbce4b5d2668b2a','9d7cd3c32f7ce287afde1e09ff73e6c6']"

   strings:
      $hex_string = { a824f017f48f904b84965e7fef2b4237d439129d751572f762cc84189fb6a63aec4dcf40c8a0855b4ce77a803b6388c828a7b3f2e0347968e597f68b215d7243 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
