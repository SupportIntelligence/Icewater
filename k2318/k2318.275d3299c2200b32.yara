
rule k2318_275d3299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.275d3299c2200b32"
     cluster="k2318.275d3299c2200b32"
     cluster_size="19804"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['35c1debb32fa8fcaafd907fd0896207f3d16b98a','71a327817e71ae717744be2807a38ba40b754bb7','b3743266279fc22f77c702f5e9fd0e479ff23749']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.275d3299c2200b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
