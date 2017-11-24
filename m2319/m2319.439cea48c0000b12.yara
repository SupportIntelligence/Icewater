
rule m2319_439cea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.439cea48c0000b12"
     cluster="m2319.439cea48c0000b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['181d4c55cf2de0f1e8b527543eecd987','22ca4c9daeb0502f46e66c7d6c9272b9','e0da2990ab7a1a7691325ec8d46867de']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323139333836333126616d703b733d626c6f676c696e6573223e0a3c696d67207372633d22687474703a2f2f777777 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
