
rule j26bf_511cbc49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.511cbc49c0000b32"
     cluster="j26bf.511cbc49c0000b32"
     cluster_size="177"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy starter malicious"
     md5_hashes="['2e90e32ac36e3ee8272b97868c86f78fd2ee484c','746ff8e3498fa8c50827354fee38543cfb684341','36452e3a87b6c2b3f5a4e380058785dc9d52a7f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.511cbc49c0000b32"

   strings:
      $hex_string = { 00460180000600c401e7000e00570241020e00700241020e009d0285020600c702b4020a000603df020a001e0313000e00530336030600880368030600a603e7 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
