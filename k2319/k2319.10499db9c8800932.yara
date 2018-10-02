
rule k2319_10499db9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10499db9c8800932"
     cluster="k2319.10499db9c8800932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5283ed6c7abe0766b1d79f5fe9d9646088920c5d','fd44490a6a9fcc8e8f9a9acd119514a085036a01','423fea11d182c09afdc50a21db01e113e3080ef2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10499db9c8800932"

   strings:
      $hex_string = { 43293f226f223a283132302e2c332e3537304532292929627265616b7d3b76617220753953314b3d7b275a3156273a27272c2778314b273a66756e6374696f6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
