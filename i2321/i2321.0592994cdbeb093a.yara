
rule i2321_0592994cdbeb093a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.0592994cdbeb093a"
     cluster="i2321.0592994cdbeb093a"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['7853131c71d3109f7b66f99930665a8e','8c2d97115b76bf029fd7edebbe27d89a','c63f8e1013ea8f4887bfa8a598e0974a']"

   strings:
      $hex_string = { f75766cfdaa1ebb34f457c2b6c8f8bd986986d7576f5a9b475c7ecb763031faa9ecbefc6a6fceebeb9a3f6e6c08a4ab6ee81285895374d671eddf9e5875f6ec9 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
