
rule ofc8_6934c699c6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.6934c699c6210b12"
     cluster="ofc8.6934c699c6210b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware smsreg smspay"
     md5_hashes="['302b81ef4b47fe4cf36bc6e5747e3f05e1642d84','1a0f8c6d5d78c4fda2bd889153b514fdb1061402','2461ecd1cb03e9f2761a77fb44452388463ce141']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.6934c699c6210b12"

   strings:
      $hex_string = { 2a95ebb05ae5aac93376e8afed07929635ca4b403f119a347d388d20a6c67f50ace659ff2225e09cbf87cb7cc729e73bea66130d3c981adaa99f449484bc6881 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
