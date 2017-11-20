
rule i3ec_06b5994cd3eb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.06b5994cd3eb0932"
     cluster="i3ec.06b5994cd3eb0932"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['4c85209c8e9736908bcb409349215374','56fb13d5c02d7acb7420ceeab902f54e','f6a3dd7ad0ba1dbb21b9bbb53c05f531']"

   strings:
      $hex_string = { f75766cfdaa1ebb34f457c2b6c8f8bd986986d7576f5a9b475c7ecb763031faa9ecbefc6a6fceebeb9a3f6e6c08a4ab6ee81285895374d671eddf9c5875f6ec9 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
