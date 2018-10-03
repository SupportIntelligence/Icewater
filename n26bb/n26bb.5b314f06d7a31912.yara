
rule n26bb_5b314f06d7a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5b314f06d7a31912"
     cluster="n26bb.5b314f06d7a31912"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys heuristic malicious"
     md5_hashes="['702dca507a91035619613ba412107c5f080135d3','4569cca10ec26ad4b73cabd4157c7ffd2457bba2','ce4d1689b5b15bb2db940b0e614cbb290bede0c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5b314f06d7a31912"

   strings:
      $hex_string = { 310300a1f471bb2bcb66ddb175f00590b5d216dc44d8b3ee43866ff82e75eb469d3a0147a0509abe12efb64ba3580f8cbfe5c06d4c1d73378b92571556594594 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
