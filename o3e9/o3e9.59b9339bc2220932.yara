
rule o3e9_59b9339bc2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59b9339bc2220932"
     cluster="o3e9.59b9339bc2220932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur cryptor"
     md5_hashes="['a336978d97c884b6f0b8d10d67aa9169','bd96c426fcb8db2a75854e6373e4d4dc','c8d48269c1ed0fcddbe42585b95971a1']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
