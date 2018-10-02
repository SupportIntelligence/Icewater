
rule k2319_3a1c86b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a1c86b9caa00b12"
     cluster="k2319.3a1c86b9caa00b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['74a1431c4dcddcb6a2849a2aa97595fc51fc4769','c00969303d403948faf9cc64a47100bfd84e279a','b1ccade593d1ee87294d8cb0ab7e3d54e233e6fb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a1c86b9caa00b12"

   strings:
      $hex_string = { 475d213d3d756e646566696e6564297b72657475726e204d5b475d3b7d76617220563d283130392e3545313c2834312e3245312c30783845293f30783233313a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
