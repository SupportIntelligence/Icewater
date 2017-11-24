
rule j2321_1a3a7a5cd6eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.1a3a7a5cd6eb1912"
     cluster="j2321.1a3a7a5cd6eb1912"
     cluster_size="57"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="spyeyes upatre generickd"
     md5_hashes="['032f7b5f255e83927b62cfededc03030','0495a17f100a7f4c3a22c597fad113b6','5b0e07fe91b69adecfaaa0e652706f21']"

   strings:
      $hex_string = { a824f017f48f904b84965e7fef2b4237d439129d751572f762cc84189fb6a63aec4dcf40c8a0855b4ce77a803b6388c828a7b3f2e0347968e597f68b215d7243 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
