
rule n231d_19bc6a92d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.19bc6a92d6c30912"
     cluster="n231d.19bc6a92d6c30912"
     cluster_size="459"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['ab1dd26a2d92821fa6e5ee7c8be39e5d0d091e85','c0eebc9af1b76609e8b4a148320771a15a383892','4f598f394bef0e5b0ae43483ead032fe27b456c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.19bc6a92d6c30912"

   strings:
      $hex_string = { 93cee3ed3303c6ddf5559d36afbfa379884f8373274dd32c220fdebe661668094618d1f2a17bcb392a4150281d4384295334964a99dc76f962bdfeca1b176f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
