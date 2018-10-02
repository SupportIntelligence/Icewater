
rule k2318_27534a46cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534a46cbeb0b12"
     cluster="k2318.27534a46cbeb0b12"
     cluster_size="189"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['bb787932841e394c8178aa1b024e90dda05d6044','d0da2fcd455a94d42bc5c8b1eff64c899e4e05f4','e56c2f683b20af5c1a8f450a0c32764124357b38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534a46cbeb0b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
