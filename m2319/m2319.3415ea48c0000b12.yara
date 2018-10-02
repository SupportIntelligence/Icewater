
rule m2319_3415ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3415ea48c0000b12"
     cluster="m2319.3415ea48c0000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html script"
     md5_hashes="['f0cb0d2d244b0dcee00f7ebc16d8049929cd393c','5fd094e411eb8122b867ef75d8f59716fa95eda1','84b7c37f19453f9485c1bfbb8f2af1b461b9639b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3415ea48c0000b12"

   strings:
      $hex_string = { 5b6439585d5b27636c69656e744c656674275d7c7c59292929297d3b7d2c49383d66756e6374696f6e2049382862297b76617220453d22303132333435363738 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
