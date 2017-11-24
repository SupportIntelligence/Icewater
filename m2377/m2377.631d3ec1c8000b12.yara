
rule m2377_631d3ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.631d3ec1c8000b12"
     cluster="m2377.631d3ec1c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['1cf733e9e3ab3824820ac27388999c25','5ffa62da17d9cca263a69fa778eda69c','c5754ccebb75c9725e625b85692d5094']"

   strings:
      $hex_string = { 6465723d273027207372633d27687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d505144782d6a6e4c44726b2f5554426c696c7a57474e492f41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
