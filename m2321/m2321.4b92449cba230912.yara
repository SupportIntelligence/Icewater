
rule m2321_4b92449cba230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b92449cba230912"
     cluster="m2321.4b92449cba230912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality vobfus jorik"
     md5_hashes="['135f11cf816745e287e15357522cc43f','511b913f6de88c219f12ce7195e4941b','f147bdc08c6f04a78ae4a4fdff54449d']"

   strings:
      $hex_string = { fdd3dd62066d2b05c374eaa47cefaf853370b5a6410a8d96a33652c60190e1aaedd1db1f61d78223f2ee60f4f54bb9f6c868bf854857862479b4e20075329a44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
