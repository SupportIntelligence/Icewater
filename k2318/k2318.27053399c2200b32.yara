
rule k2318_27053399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27053399c2200b32"
     cluster="k2318.27053399c2200b32"
     cluster_size="5291"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['1daa9d1c580cc8cf475fb0b9adfb06ec8b3222d1','2fbfc395c9729c5918750baed38db8ff85a910ce','57f5b29cb3673c8644088cc3f550c112a06859bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27053399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
