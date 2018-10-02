
rule k2318_27115ba9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27115ba9ca000b32"
     cluster="k2318.27115ba9ca000b32"
     cluster_size="1003"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['8b3888ebc33f6e4d64d541273e57b142c745e95c','bf5fb8d0805cc1b37adba71b56c5c69ccdb780b5','f8db1bc25341c0e19e6a16dcea793943a3ae3c7f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27115ba9ca000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
