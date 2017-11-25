
rule m2321_0991aa0dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0991aa0dc6220b32"
     cluster="m2321.0991aa0dc6220b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality atbh backdoor"
     md5_hashes="['0886a5a405e962c6734374c63ed6d6f5','18f7b369a774db69f831bec787fb3690','6f1aa70583184e6fef90bd4fb6bc6d21']"

   strings:
      $hex_string = { 7ea0b34d9293ad3846432fc7e08c826406fae8cd7542ae26d3ed2b6049f210bcc507797298323c00f64b37ec95f409e45d3e80b20b784674d6fc65d539e7cc30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
