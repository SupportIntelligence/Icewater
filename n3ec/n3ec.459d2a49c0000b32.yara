
rule n3ec_459d2a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.459d2a49c0000b32"
     cluster="n3ec.459d2a49c0000b32"
     cluster_size="1023"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="attribute highconfidence malicious"
     md5_hashes="['008f08044d50d532531db137abdf7dde','009f49619ae7235fbd8c57210ecb7418','03cabda8753c37d8e1a19864417b288e']"

   strings:
      $hex_string = { cc8b4df0e91855fdff8b5424088d420c8b4af033c8e85b73feffb8f8ed4300e9bda3feffcccccccccccccccccccccccccc8b450850e8ff7afeff59c38b542408 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
