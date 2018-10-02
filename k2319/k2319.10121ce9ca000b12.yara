
rule k2319_10121ce9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10121ce9ca000b12"
     cluster="k2319.10121ce9ca000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['cfb9f4dd61c34e65e28cada07137c9637ce880c9','3eb6196f43d4366df8b9cffcb2a0f36e251f8af9','96228be986a0810b5a8fba151878e168b85681f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10121ce9ca000b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20435b7a5d3b7d76617220533d2835372e3c2830783234442c36352e293f2833382e3545312c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
