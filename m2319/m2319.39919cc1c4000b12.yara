
rule m2319_39919cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39919cc1c4000b12"
     cluster="m2319.39919cc1c4000b12"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['319241de3bbb9a2005a6d0710590ebe6','4d665af7151cd4a0c604657a8052125a','feaa6c62a8a43935b55213bb8d43bee3']"

   strings:
      $hex_string = { 6865696768743d27373227207372633d27687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d457936564f54324c4873512f5548757753674c7572 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
