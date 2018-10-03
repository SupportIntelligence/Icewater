
rule n26d7_5116ba41c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.5116ba41c4000b12"
     cluster="n26d7.5116ba41c4000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor loadmoney cryptor"
     md5_hashes="['c47c48f472474218039f930a0eca2fe64479431a','4a20e232580c3e027782325d8073306f95926229','537a15bc54b0a3a27788764ecaec150dff351cc1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.5116ba41c4000b12"

   strings:
      $hex_string = { 7899838a2f4ebf45cfc23a3a463abc6a6e9a5c36cd6c551ba83c23a97d000000a3a761b76bec8f8271e7c931263889baafc8bf518228bd39944d54441dcaee38 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
