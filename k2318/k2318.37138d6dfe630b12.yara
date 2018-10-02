
rule k2318_37138d6dfe630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37138d6dfe630b12"
     cluster="k2318.37138d6dfe630b12"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['534a4cfb1d67d77b99cc66170b678e28246772bb','b6ca79fb7358f228bac8ac27dfe98312971881cb','15a5345082a171c50ae46c38677a0b6aafd9ef2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37138d6dfe630b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
