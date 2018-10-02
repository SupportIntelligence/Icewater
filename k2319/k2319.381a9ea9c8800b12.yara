
rule k2319_381a9ea9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381a9ea9c8800b12"
     cluster="k2319.381a9ea9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['77bacf3a910bde2fcf62a4672911b5f9bd0f7c2d','7757930f0d4e8fd657f9b5882756135581c6575a','6716bf29ee144c6bc4bbb2b315d842d7ba3cedb8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381a9ea9c8800b12"

   strings:
      $hex_string = { 27573270273a225455564d222c276b306c273a2866756e6374696f6e28297b76617220753d66756e6374696f6e284f2c64297b76617220793d6426283130343c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
