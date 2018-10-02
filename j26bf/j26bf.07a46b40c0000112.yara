
rule j26bf_07a46b40c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07a46b40c0000112"
     cluster="j26bf.07a46b40c0000112"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy tsklnk dotdo"
     md5_hashes="['27ba58221e5414362fc4605918c8ed7de3134aff','0bb682ca2058d6709e04ff8711a3b09082605334','05c7382ac7074f2ccb5cea15d5d107109b12581a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07a46b40c0000112"

   strings:
      $hex_string = { 7269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c6541747472696275746500477569644174 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
