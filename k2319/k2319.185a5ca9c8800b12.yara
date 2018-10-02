
rule k2319_185a5ca9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185a5ca9c8800b12"
     cluster="k2319.185a5ca9c8800b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['aae6ae55c2ef05cf173f62b891614bccd5bce30c','f2256385b3a1dbab0429b4e644293ab66ec32fac','355f65b327feb3e897b5bbb23468b9885a4f0c3e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185a5ca9c8800b12"

   strings:
      $hex_string = { 627265616b7d3b666f72287661722064376720696e204d36583767297b6966286437672e6c656e6774683d3d3d2828342e3545312c3335293c38383f28307844 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
