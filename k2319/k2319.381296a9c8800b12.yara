
rule k2319_381296a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381296a9c8800b12"
     cluster="k2319.381296a9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['28bd193901d7c8c886f99fc738b28aa61601ad88','2c84bd706cf4fe6c6d48cec9305380cbf1cc33fd','f3729d40f5362e0b1b02c14aaf143f9068a7e15b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381296a9c8800b12"

   strings:
      $hex_string = { 27573270273a225455564d222c276b306c273a2866756e6374696f6e28297b76617220753d66756e6374696f6e284f2c64297b76617220793d6426283130343c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
