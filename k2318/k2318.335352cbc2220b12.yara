
rule k2318_335352cbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.335352cbc2220b12"
     cluster="k2318.335352cbc2220b12"
     cluster_size="184"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['51fb203548fa7da9ae49132eefd40ae4d33bab76','51b1cd7033d1739d623b702e64d2f2e4a69d9af1','974e3b36dd153ee1882311fa06bd804c88e930b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.335352cbc2220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
