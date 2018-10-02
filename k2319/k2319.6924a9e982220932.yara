
rule k2319_6924a9e982220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6924a9e982220932"
     cluster="k2319.6924a9e982220932"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['af010b0d9cc2accca320fc23555cc5b43c0a5897','0645a424fc48bf020dd727ff6f4ba8f4b32257cd','8ed23c113c807071f0c88adbdfdc425ab22eae27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6924a9e982220932"

   strings:
      $hex_string = { 313139293a28307836382c3078313738292929627265616b7d3b76617220423074363d7b27683355273a2241222c276d3371273a66756e6374696f6e284e2c4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
