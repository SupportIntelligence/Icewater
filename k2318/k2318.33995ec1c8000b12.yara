
rule k2318_33995ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33995ec1c8000b12"
     cluster="k2318.33995ec1c8000b12"
     cluster_size="486"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['a40735289ed1496b3e7b1cca381691c6c1a11074','cfc3213999ac587a6afc6bd88dacb05bd5b0c6af','7d68ec50a945532c9b8648ca80b1ecb1ac61a724']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33995ec1c8000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
