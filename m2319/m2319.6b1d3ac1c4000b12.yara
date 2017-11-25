
rule m2319_6b1d3ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.6b1d3ac1c4000b12"
     cluster="m2319.6b1d3ac1c4000b12"
     cluster_size="30"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['028d56a84862114d1efb36edc7916cbe','0e4a22bf83a82635ac3ba25e1f8b58a1','7801158c2aa6272b47433cf31d4c90ea']"

   strings:
      $hex_string = { 6465723d273027207372633d27687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d505144782d6a6e4c44726b2f5554426c696c7a57474e492f41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
