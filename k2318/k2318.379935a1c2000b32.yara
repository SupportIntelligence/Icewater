
rule k2318_379935a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.379935a1c2000b32"
     cluster="k2318.379935a1c2000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['1a4a7b78847f1785fe0c2780da43230c44b1ed45','6dc463ebb513f88babd2dc4cd7b4c44461d87548','525a75b49b0abc33b90e027327371564affefe7a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.379935a1c2000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
