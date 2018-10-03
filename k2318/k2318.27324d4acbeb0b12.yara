
rule k2318_27324d4acbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27324d4acbeb0b12"
     cluster="k2318.27324d4acbeb0b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['4f601c54231d330eb046268982b685565cb5cc9b','0d84abb9b1c3659d22547a5db19901ce2d4b0fd5','55aba435d72ffd91f343512eba33f92da82fba85']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27324d4acbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
