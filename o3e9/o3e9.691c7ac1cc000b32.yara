
rule o3e9_691c7ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.691c7ac1cc000b32"
     cluster="o3e9.691c7ac1cc000b32"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur gena"
     md5_hashes="['2e18be1d31088fe08af822a067d64f11','3831073f83a41e0be8cbd680a1e92579','eac42d8bc73e5aace64df1ed48d66bd8']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
