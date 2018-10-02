
rule k2318_23135ba9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.23135ba9ca000b32"
     cluster="k2318.23135ba9ca000b32"
     cluster_size="435"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['307edd6864a4a2c8b01c19c96ff887c924c1ff9c','53aa7a81fcb495c03e1f206e2ff4025eb12dbd72','84d125fce897526e02e41bb42a5b7c7ac8b77b77']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.23135ba9ca000b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
