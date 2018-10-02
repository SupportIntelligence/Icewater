
rule k2318_2752544addeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752544addeb0b12"
     cluster="k2318.2752544addeb0b12"
     cluster_size="123"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['ecb3cdb7b3d2f7f5e9b166b4291e9b4f81dbbe6a','cb8427d15bfb900adb5a4d596ce00f296c7d6efb','98e9f47b4ab73ca27b1c8ca06d32b53fd83b7854']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752544addeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
