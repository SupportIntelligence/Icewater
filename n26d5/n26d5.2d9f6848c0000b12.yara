
rule n26d5_2d9f6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9f6848c0000b12"
     cluster="n26d5.2d9f6848c0000b12"
     cluster_size="55"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['593d6bc07b2c9ef309d871559d7807a299d80934','e00f410a07e2b80e322d5ef9664ff0a7f04b7429','0ab4606d06336c9e5d2e142a57e4ce41e3d44671']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9f6848c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
