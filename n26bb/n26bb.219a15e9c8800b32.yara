
rule n26bb_219a15e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.219a15e9c8800b32"
     cluster="n26bb.219a15e9c8800b32"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mikey bunitu kryptik"
     md5_hashes="['6d1e36f2ac74cb91ff9c7cc680ff532a5774d8c3','d8d33ac61ed547f28974a578a2d27c77b9d46e79','b90aa497df4815cac02ccc805cc0a0731271a268']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.219a15e9c8800b32"

   strings:
      $hex_string = { 706b6f8f426a63754a6c658e756d72801e1f7855331f2077716d62c94a5b4bc05a4c6fc65e663d12322d3950632e344c1d3463be6129641321200a0963666710 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
