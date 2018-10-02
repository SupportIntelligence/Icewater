
rule m2319_43a33554dd9b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.43a33554dd9b0932"
     cluster="m2319.43a33554dd9b0932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script injector"
     md5_hashes="['bd87711837f9d34fa221b2445c2de421a777abf2','e24c8ef908994df38446f86983467b2a46164b7a','e7270ced60a3536b436a9b9b01d9330d1e0960a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.43a33554dd9b0932"

   strings:
      $hex_string = { 3c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a22687474703a5c2f5c2f31393630736d6f766965732e636f6d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
