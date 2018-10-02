
rule k26bb_6ab2d794de6b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ab2d794de6b1912"
     cluster="k26bb.6ab2d794de6b1912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis attribute"
     md5_hashes="['c02fe8a764cb40b5fef117dc0e38f2d0ba92fe64','c3b588a55faf70475d9b6b03f4782da9a6ab5d8d','2ecd5980b5566e41736fe5277dab47478fddb4cc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ab2d794de6b1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
