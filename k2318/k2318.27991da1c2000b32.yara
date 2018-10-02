
rule k2318_27991da1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27991da1c2000b32"
     cluster="k2318.27991da1c2000b32"
     cluster_size="409"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['bc7caf8a11e400b45188a4211421dd08d82b7b36','1bf84c8783bb516b13b358a7bdbeaf90336c0536','ed3ba44179e7303fa7fbbbe1b5bd8e6a022b2910']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27991da1c2000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
