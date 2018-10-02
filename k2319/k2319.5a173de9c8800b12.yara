
rule k2319_5a173de9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a173de9c8800b12"
     cluster="k2319.5a173de9c8800b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['e6d74aedc7329956828ce0c7ab02dc03e16279f5','213b6d29320e09efe8d2db529cf20e313fc56f91','a6ab7c459114eb7405df0faada3feef7020c9f4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a173de9c8800b12"

   strings:
      $hex_string = { 445d213d3d756e646566696e6564297b72657475726e20705b445d3b7d76617220543d2831342e313645323e2838332c3132302e293f2833332e2c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
