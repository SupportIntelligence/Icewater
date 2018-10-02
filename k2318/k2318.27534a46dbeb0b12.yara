
rule k2318_27534a46dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534a46dbeb0b12"
     cluster="k2318.27534a46dbeb0b12"
     cluster_size="188"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['f6776c58105599fe612330bc19c1edd9f1d66f27','0c980787b0f185392a2ee7dc9419f418a7acb0c7','38589ebd2459aac7d922b5ee0e0b6e3809bf2769']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534a46dbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
