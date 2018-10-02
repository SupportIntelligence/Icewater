
rule k2318_37138b6dfe630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37138b6dfe630b12"
     cluster="k2318.37138b6dfe630b12"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['b638470881ff6ff6ef18df1e4a29c22a98abb8fb','98468adde5c88e33d3917abccc016d4fc13ef3ed','720c4aff9dad0aeae0d3dd6b008fabbb024697b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37138b6dfe630b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
