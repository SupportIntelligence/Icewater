
rule k3f6_0048b64cc3080011
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f6.0048b64cc3080011"
     cluster="k3f6.0048b64cc3080011"
     cluster_size="7"
     filetype = "data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis escyac score"
     md5_hashes="['331dbaafb8489ed7b40828c598459988','3379c308d0bbd1cd1e167c65f86b3f78','feecf6996e0835f26f33f6b34b273110']"

   strings:
      $hex_string = { 0000001400000091000005e200000000000000ffffffffffffffffdbffffff0d0000000d00000000000000010000000000000000000000000000001f000000f1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
