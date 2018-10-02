
rule k2319_1e1592b9c9000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1592b9c9000932"
     cluster="k2319.1e1592b9c9000932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['55cc0e49f39eb8e6b3fa90a12bb7be23b2ea463a','8cda45c0753cfd6634534b1bafb9f24d1342d21d','ed400842ef43f198ae14d4456cd8e046b50d8112']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1592b9c9000932"

   strings:
      $hex_string = { 46293c3d30783234433f2837332c313030293a28307835382c39362e324531292929627265616b7d3b666f72287661722070304420696e206532563044297b69 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
