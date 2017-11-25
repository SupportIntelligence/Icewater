
rule m2319_19993ac1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.19993ac1c4000b32"
     cluster="m2319.19993ac1c4000b32"
     cluster_size="12"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['190656eeb50dc8d30575e28100fb705c','2fab87f869bfdd08aaf032d9087f159d','f1e59e78b68dc454d738ae736bf39aa5']"

   strings:
      $hex_string = { 6465723d273027207372633d27687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d6a67434a62766669717a302f5550374f4a52476b5a57492f41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
