
rule m2319_3b9d1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b9d1cc1c4000b12"
     cluster="m2319.3b9d1cc1c4000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['813f96223c9de35de454ff1dbb7869da','dc61a4f6ad8ef18774192c873450dcae','f85f766cbbb1de03c2f597dcf623c74b']"

   strings:
      $hex_string = { 65696768743d27373227207372633d27687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d4942366b796764754c6e382f553553414b696b574857 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
