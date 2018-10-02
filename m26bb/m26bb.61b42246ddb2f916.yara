
rule m26bb_61b42246ddb2f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.61b42246ddb2f916"
     cluster="m26bb.61b42246ddb2f916"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor virut malicious"
     md5_hashes="['c62db665d6e2674542da11a3d337160b2cdea8f9','46571f5653cbab0429b02e7ed23ef0cb3ee29c11','19f457b600988edc72f36b948ee2387e82402e91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.61b42246ddb2f916"

   strings:
      $hex_string = { 0a508ea265287eaacc07fff7d917a93ff922bab7d557d4162baff5918503bd068fa83864fafcdbf33705b1f207d186edbbe8c6f5ebc2f4bf74e992f0fb9b3469 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
