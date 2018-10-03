
rule k2319_581a9699c6200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.581a9699c6200912"
     cluster="k2319.581a9699c6200912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0cbe726caa99983ec8cdec4c612a24626fa6aace','d8d7a62916beca7c811c75d453ea9242e1433f31','4ad4f992c369bfbd4c59da6cdea6de9fc009632a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.581a9699c6200912"

   strings:
      $hex_string = { 66696e6564297b72657475726e20415b455d3b7d76617220533d282835382c3078314545293e3d3132373f283133392e2c30786363396532643531293a28332e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
