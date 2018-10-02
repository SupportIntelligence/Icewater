
rule k2319_38129ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.38129ce9c8800b12"
     cluster="k2319.38129ce9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4bccfaf99acd5598ebc53f8ae6d15547e6b03f6f','0b7c6d4ac07f36b6ec6e2e5f90bd11a5e11a236e','1e5a3d48f49866af1e133debc31e6fb45c01d45b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.38129ce9c8800b12"

   strings:
      $hex_string = { 27573270273a225455564d222c276b306c273a2866756e6374696f6e28297b76617220753d66756e6374696f6e284f2c64297b76617220793d6426283130343c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
