
rule p26c9_11bd6949c0001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26c9.11bd6949c0001912"
     cluster="p26c9.11bd6949c0001912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious filerepmalware"
     md5_hashes="['7e9185630e23947f41943b471c4d97a534b62dfd','38f424ed48d183f2f17acac7ec9561cd83702c2f','a3af6bbd6db5078e5bc0386d59d2e19e16dfd3e7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26c9.11bd6949c0001912"

   strings:
      $hex_string = { 5341b203eb6d80fb21741c80fb6974098d43913c027610ebab66837e0200c685700d010001759d440fb6d3448954244084db749033db4c8d0d570afeffe94901 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
