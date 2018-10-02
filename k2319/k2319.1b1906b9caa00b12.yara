
rule k2319_1b1906b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1906b9caa00b12"
     cluster="k2319.1b1906b9caa00b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b842f581d5edf9b51e864454816ed535a4810879','e3ecaa1fcb8a809c41e0fe2646d6044b4271b16e','c3e66a6c1c4af79839ebce842a4c04283c1d1bd2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1906b9caa00b12"

   strings:
      $hex_string = { 696e6564297b72657475726e204b5b475d3b7d766172204c3d2836382e313045313e28312e31383345332c313333293f2830783133412c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
