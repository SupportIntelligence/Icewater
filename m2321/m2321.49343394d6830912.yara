
rule m2321_49343394d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49343394d6830912"
     cluster="m2321.49343394d6830912"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0696b956365fbd737f1dbaf03b476c44','17c6823682e9f1a8192a14c64a37a013','d5873b12c78e06eb0124c2b4a5824084']"

   strings:
      $hex_string = { 1cc88fcdaa15cbe4fb10030640c3fe7463f411e0bb709aa133de647b2e8f4f78bfc9dc82b41af60bc6f8099d4de653e86a32b71e3b76e57e677a95d3fc4c262a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
