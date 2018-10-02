
rule k2319_791f6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.791f6a49c0000b12"
     cluster="k2319.791f6a49c0000b12"
     cluster_size="97"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script browext"
     md5_hashes="['7882706e1a8c94ff7b8506f611a517bf2cea5a58','7c8773ea1b59524d9c5771a8fa829aa6e2365cc1','dbf1459ba86e7f62c5374559ae4fbbace795d8b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.791f6a49c0000b12"

   strings:
      $hex_string = { 2e5739432b4e3148352e5a39432b4e3148352e473243292c6465636f64653a66756e6374696f6e284f2c4d297b76617220583d22385f222c5a3d227574222c42 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
