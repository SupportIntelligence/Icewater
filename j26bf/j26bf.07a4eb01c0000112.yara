
rule j26bf_07a4eb01c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07a4eb01c0000112"
     cluster="j26bf.07a4eb01c0000112"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy dotdo tsklnk"
     md5_hashes="['f6abebf722f636da40b304f881120a30c4447dd9','ec2022f9fb73963fd9cb9b133907c7bd4281ce4a','a997d7565afda64bd126c9ad069d5e3599715158']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07a4eb01c0000112"

   strings:
      $hex_string = { 747269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c65417474726962757465004775696441 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
