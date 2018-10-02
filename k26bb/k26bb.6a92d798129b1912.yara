
rule k26bb_6a92d798129b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d798129b1912"
     cluster="k26bb.6a92d798129b1912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis adwaresearchprotect"
     md5_hashes="['b36fd89a9514cf31203c88dd4b99a9afd3adb4c5','93ed4648f2d7670e083f43758d5fb14f1aff5352','db28561077ffba58aa1e69b4fbbdd901d2dcd26c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d798129b1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
