
rule m3e9_0991ca0dc6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0991ca0dc6210b32"
     cluster="m3e9.0991ca0dc6210b32"
     cluster_size="31"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality backdoor poison"
     md5_hashes="['0836c79331fe6f18f2824665029f6980','2b3e5671d76eee7e746cae7ba0920248','88494816e4d54e07fd2f547835b81189']"

   strings:
      $hex_string = { 7ea0b34d9293ad3846432fc7e08c826406fae8cd7542ae26d3ed2b6049f210bcc507797298323c00f64b37ec95f409e45d3e80b20b784674d6fc65d539e7cc30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
