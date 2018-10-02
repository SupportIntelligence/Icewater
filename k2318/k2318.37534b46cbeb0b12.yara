
rule k2318_37534b46cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37534b46cbeb0b12"
     cluster="k2318.37534b46cbeb0b12"
     cluster_size="69"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['54a4110ddf36962fb48e4b3682d1494d5113259e','3c884c410735278b64d33b1ef7b2356b3bdc7e08','41d22635bd06e92494cd1fe5cb98a5c6b19f219a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37534b46cbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
