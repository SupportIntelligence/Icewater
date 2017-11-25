
rule m3f7_591b96c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.591b96c9c4000b32"
     cluster="m3f7.591b96c9c4000b32"
     cluster_size="61"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['02c167165205cb39267a270e66b4d01e','049306e0a2ec5c4679d141ee32c85010','4929b56d264f8428f60284a27e1fed24']"

   strings:
      $hex_string = { 3936303330313636355c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794e6d5a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
