
rule k2318_2752c4c9c2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752c4c9c2220b12"
     cluster="k2318.2752c4c9c2220b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['551a9814d0a9ede19a3ae470bd63a9db51159c5a','abf69c7040197f4f5c609cafc06f9962b6a44604','ec570addc34f20cb4f04f43493b015903fa05ec5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752c4c9c2220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
