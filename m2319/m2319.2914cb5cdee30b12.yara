
rule m2319_2914cb5cdee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2914cb5cdee30b12"
     cluster="m2319.2914cb5cdee30b12"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script fakejquery redirector"
     md5_hashes="['06a07c2e158e419dfbefbf87ec209185','1754462d1726cbc5e03e162fd232a60e','fde01803c8b77664ccb25b0741083e43']"

   strings:
      $hex_string = { 617265617c627574746f6e2f692c243d2f5c5c283f215c5c292f672c4a3d7b49443a6e65772052656745787028225e2328222b4d2b222922292c434c4153533a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
