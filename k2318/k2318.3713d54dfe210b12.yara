
rule k2318_3713d54dfe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713d54dfe210b12"
     cluster="k2318.3713d54dfe210b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['eec465681b012c52bfb4bc81df0565c12b74a3d2','f6864f2e529acb7075023ed5e47a02035bf648b2','5f41d0e616e6f31888ca025ef5b0a68993b26d1a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713d54dfe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
