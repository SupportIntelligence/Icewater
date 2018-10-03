
rule j2328_2ba6b6469e9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.2ba6b6469e9b0b12"
     cluster="j2328.2ba6b6469e9b0b12"
     cluster_size="306"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit html"
     md5_hashes="['9723d8a4b53bd94db320cce8c92992bb5d4e7d8c','3b2492f2926032fb93db6d91027ae1520fc5f053','629268bf51818383619161d8d7661cb76f5b1de7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2328.2ba6b6469e9b0b12"

   strings:
      $hex_string = { e7acac3337e5b186e6a0a1e99a9be8889ee8b988e6af94e8b3bd3c2f7469746c653e0a2020202020203c6c696e6b3e687474703a2f2f656d6d70642e6564752e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
