
rule k26bb_6394b3f9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6394b3f9c2200b16"
     cluster="k26bb.6394b3f9c2200b16"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut attribute"
     md5_hashes="['caa88d929c1ff90215f8d3137df15c46f5238767','092236af6de2a212b349af38c5fa060b2917b3ba','023b0a61a19d3bb682e90095e83d3e744bccc4c4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6394b3f9c2200b16"

   strings:
      $hex_string = { 7508ffd685c07511403945f4740dff37ff15fc10000183270033c05f5ec9c20c00cccccccccc8bff558bec83ec1c538b5d0c8b43085633f63bc6740f50685c04 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
