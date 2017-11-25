
rule m3f7_591a94e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.591a94e9c8800b32"
     cluster="m3f7.591a94e9c8800b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0d4d32d1ec6362ca64e062fad09b0205','28a95d2d3fffa608924b4c7f799bd451','cfb815d90cc76c8c00eea29fc7bdd497']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3230303039343534383632373830363531303226776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
