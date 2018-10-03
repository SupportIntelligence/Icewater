
rule k2319_339b1c99c6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.339b1c99c6200b32"
     cluster="k2319.339b1c99c6200b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html script clicker"
     md5_hashes="['0b57bd8eaffe498c8bed497d28248e99c0d3f065','332838530825d072c89fad4fcc8dc940a10e5bb7','e2561f0359c91a866f943389b11fbd47b09cdb64']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.339b1c99c6200b32"

   strings:
      $hex_string = { 676f72792f64726976655f66312f223e46313c2f613e3c2f6c693e0a09090909093c6c693e3c6120687265663d22687474703a2f2f7777772e62657374657870 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
