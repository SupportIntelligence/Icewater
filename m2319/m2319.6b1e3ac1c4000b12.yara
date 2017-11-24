
rule m2319_6b1e3ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.6b1e3ac1c4000b12"
     cluster="m2319.6b1e3ac1c4000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack script"
     md5_hashes="['032cb55052bb4beeb656a9589205e183','0b9fc391a8cf141679be8b61cad91a34','25cb5325d7c7c6d450c1bdc07ad36932']"

   strings:
      $hex_string = { 6465723d273027207372633d27687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d505144782d6a6e4c44726b2f5554426c696c7a57474e492f41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
