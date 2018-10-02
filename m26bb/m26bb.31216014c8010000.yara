
rule m26bb_31216014c8010000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.31216014c8010000"
     cluster="m26bb.31216014c8010000"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genericrxek"
     md5_hashes="['af685619c433c3ef04c34003350e023892da7065','9ed25dc720924a579fd55f42365b7f5af0a7fa9a','f2cfc8eea4dfdd44b4c6007577fbc6dc3dd2e45e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.31216014c8010000"

   strings:
      $hex_string = { 634578004003536c65657045780042024c6f61644c696272617279410074014765744d6f64756c6546696c654e616d65410076014765744d6f64756c6548616e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
