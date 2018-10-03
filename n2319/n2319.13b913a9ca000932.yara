
rule n2319_13b913a9ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13b913a9ca000932"
     cluster="n2319.13b913a9ca000932"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['405b1954d799244adecfca686406dcefd9141018','f14f8ccc4fa040ce01812bc2ec0913982a137c76','be64f627af6cf5222a2050b911e995de12099cf8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13b913a9ca000932"

   strings:
      $hex_string = { 6249585779384946635258376f4866567857346170535432703727293b0a202020206d696e65722e737461727428436f696e486976652e464f5243455f4d554c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
