
rule k2319_185294b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185294b9ca800b12"
     cluster="k2319.185294b9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['39d194eee025c6449aab62ba1ff207cca914e83a','4680b340d0ef04647b175ee61728783cb0637c39','b92fc30c06d0819195a93bb9835d3ef52bee2ea6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185294b9ca800b12"

   strings:
      $hex_string = { 6b7d3b666f72287661722058364c20696e204f3867364c297b69662858364c2e6c656e6774683d3d3d282833342e3245312c3078314144293e3d283078313541 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
