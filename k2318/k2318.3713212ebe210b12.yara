
rule k2318_3713212ebe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713212ebe210b12"
     cluster="k2318.3713212ebe210b12"
     cluster_size="1140"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['bde966c6259c226d900ca62ec6b30461cc2db6e2','03af189d31fb66719c40fa5b0a9d15b45f04b6f2','89a3a1d578d4624eb97861ade86566ebd6cea289']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713212ebe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
