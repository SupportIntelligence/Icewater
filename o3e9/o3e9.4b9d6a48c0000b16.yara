
rule o3e9_4b9d6a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4b9d6a48c0000b16"
     cluster="o3e9.4b9d6a48c0000b16"
     cluster_size="90"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur gena"
     md5_hashes="['0e990dda6b2107c3601c43d6edcf0f5f','2146fb9f45865591ff07c1492cedb82b','a02ef49f032a55e96ee4a0e0d48fadac']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
