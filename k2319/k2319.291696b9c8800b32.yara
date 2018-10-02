
rule k2319_291696b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291696b9c8800b32"
     cluster="k2319.291696b9c8800b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a7af059715e448f8f3cec2a926000b9f875e612d','5d2bbda72e0c2bff27860f02d6c545214b8e7d3b','bf969ca3bdbe1b7b1b5e7f8eedd866b17fcf9962']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291696b9c8800b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e206e5b725d3b7d76617220493d2828307838332c352e354532293c32382e3645313f2834342c226a22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
