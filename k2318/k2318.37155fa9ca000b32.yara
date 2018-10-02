
rule k2318_37155fa9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37155fa9ca000b32"
     cluster="k2318.37155fa9ca000b32"
     cluster_size="104"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['92efc1376bb18052a9a5b5ca6e415a932f16effa','ccb5cfa29a285bc0363c51542b4d82d0aa796c30','6c1e4f5288d3cca4c83f0b555ca74f35e1aac01a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37155fa9ca000b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
