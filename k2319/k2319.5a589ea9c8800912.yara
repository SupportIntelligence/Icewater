
rule k2319_5a589ea9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a589ea9c8800912"
     cluster="k2319.5a589ea9c8800912"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['06a86d80db04a32a4c6fe3653c26b34f6911e666','42593d4420144cdf303aee0d65ca44f1c71b145e','7d08886ad86205d47f871a6cc5e11d28e341a000']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a589ea9c8800912"

   strings:
      $hex_string = { 77696e646f773b666f72287661722063367920696e207139493679297b6966286336792e6c656e6774683d3d3d282830783138382c3231293e3d30783134443f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
