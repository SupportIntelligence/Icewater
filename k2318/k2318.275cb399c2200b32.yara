
rule k2318_275cb399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.275cb399c2200b32"
     cluster="k2318.275cb399c2200b32"
     cluster_size="926"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['42bf67e54f2f18585d168d58335328ad08769d45','2d6e8a763d19473aeabfb5587ecd4cbb03aec755','b9956c642235d5b3ba49d6f45920df16eb793278']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.275cb399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
