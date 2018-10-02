
rule k2319_521316b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.521316b9ca800b12"
     cluster="k2319.521316b9ca800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ddbd226c4c0aeca41ece3024e713d0b0cf0b9a02','e75be5c7a93096a6707e193c3d59770a4d84a412','b92fe05ec5f7f0424c8f9b657380ae26cb3b60be']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.521316b9ca800b12"

   strings:
      $hex_string = { 3a2831322e303945322c32292929627265616b7d3b76617220493767333d7b276a39273a66756e6374696f6e28542c51297b72657475726e20543e513b7d2c27 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
