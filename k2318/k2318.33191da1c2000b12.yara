
rule k2318_33191da1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33191da1c2000b12"
     cluster="k2318.33191da1c2000b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['d61d90c0cb7f7e799287c5957d53c327f69e29c6','6b8e21eb520925c9b79dde752d9ad42059f5ebbe','84de60a90602ec18e920c57d3c7ad70d94bfd47a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33191da1c2000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
