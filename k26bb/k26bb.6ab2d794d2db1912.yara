
rule k26bb_6ab2d794d2db1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ab2d794d2db1912"
     cluster="k26bb.6ab2d794d2db1912"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis adwaresearchprotect"
     md5_hashes="['3ba80595a99a341586e9aad66365c36c2d07863c','55c240ae28ec8ac712cfff592299b2f6178f8cd4','d0912829899570e8acd11e89e7b57cbb92f8a28e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ab2d794d2db1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
