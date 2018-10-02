
rule k2318_3731012eba210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3731012eba210b12"
     cluster="k2318.3731012eba210b12"
     cluster_size="385"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['7cc35bcfc83e7c29b531a7f2f2cbea4580a7d604','722ecaa1105db1cb7a40dd9b9b8cc21527f5773b','2a165056bdd6a39f5a3440397129f347f05d84fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3731012eba210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
