
rule k2318_2753cca9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2753cca9c6220b12"
     cluster="k2318.2753cca9c6220b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['5459f3ab6f3885ca17dd9f95b5d8b9910a732e9c','25950d9b5065e9ce06a9cc4232737a389a5f0b98','9bfabc41aec2778b2b7e415189e7d297b1131c4d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2753cca9c6220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
