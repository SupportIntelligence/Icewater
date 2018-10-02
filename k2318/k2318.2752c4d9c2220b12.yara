
rule k2318_2752c4d9c2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752c4d9c2220b12"
     cluster="k2318.2752c4d9c2220b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['08bf9a3d2d8071cde558c9b9f999a87d3eb3ee5d','30a385e33691efb5874807eac95a9c0872987cea','754ffe6dd38f6d0394b7e7d08d2f68c85a0bb99c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752c4d9c2220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
