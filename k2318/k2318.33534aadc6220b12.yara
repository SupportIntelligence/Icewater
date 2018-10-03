
rule k2318_33534aadc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33534aadc6220b12"
     cluster="k2318.33534aadc6220b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['4ea30b43a976f12158b767859d2293b4b9f64619','0a9f483d1d7c13b0942e8ec7bb0751951f84a210','9d04c0fc5774fc553eb319ef2b1ba4e7477edbba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33534aadc6220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
