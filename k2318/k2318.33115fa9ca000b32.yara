
rule k2318_33115fa9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33115fa9ca000b32"
     cluster="k2318.33115fa9ca000b32"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['0ca0fb4f7b522f71c50438c45ead3c0d55adace3','086e2d35890ac4c5163fed0b36b7efaaa58d2712','fd05dc93de9e62c40e5b2acf1b3f52bbb56d8389']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33115fa9ca000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
