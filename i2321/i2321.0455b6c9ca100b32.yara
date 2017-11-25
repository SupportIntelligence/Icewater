
rule i2321_0455b6c9ca100b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.0455b6c9ca100b32"
     cluster="i2321.0455b6c9ca100b32"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['486f8c74a412f461e6f4690dfcd65343','57697e8b739cdedd72b4358c0bf89a7a','d9a5a6d8331fb90d8c2f2b126e226179']"

   strings:
      $hex_string = { 8b85107eb6e3a9cafcf3c5cab14a657e263cbdb3b258af554ad558f246abe444ad540ae11b6d4f95eac7e72f5c28566747e7aaa54238393cfef4f0e8a127b28e }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
