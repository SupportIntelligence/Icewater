
rule n26bb_3615ea96ea210b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3615ea96ea210b14"
     cluster="n26bb.3615ea96ea210b14"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="auslogics tweakbit malicious"
     md5_hashes="['7122e108837c7866ad675d7a1d323f3f3a71bf8e','3bca6a31f37ad6b6be7d5338ed18778bb26cab4d','a719e54e428c46555df57374f7d381985d3a905d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3615ea96ea210b14"

   strings:
      $hex_string = { ddce226b56bf38e6bd9b47955f948a4bcfaea81cf5f8cbbb6f0d7fe925a13467db135f77ecaafcbee22b2e6974ef21e5b74d97ca9e8608dee439d51b6e09a698 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
