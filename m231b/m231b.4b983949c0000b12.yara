
rule m231b_4b983949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4b983949c0000b12"
     cluster="m231b.4b983949c0000b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker faceliker script"
     md5_hashes="['a581de395974cf13e675929c64ad523f6430e16a','cbe49ff60825f322b53b0b97b22dcbfc3ebf83ee','d0f791c79347b49ae327ad4fe1a9889958b77272']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4b983949c0000b12"

   strings:
      $hex_string = { 323054254531254241254144702532303133273e54727579e1bb876e207472616e6820436f6e616e2054e1baad702031333c2f613e0a3c2f6c693e0a3c6c693e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
