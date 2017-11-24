
rule o3e9_019c90b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.019c90b9c8800b32"
     cluster="o3e9.019c90b9c8800b32"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="miniduke backdoor cosmicduke"
     md5_hashes="['08aba4284937433f8563cb349c28c255','23e504e3f5be20dee72765da1d648db4','fec0d9f78be3e403d1dcf62a74a6508e']"

   strings:
      $hex_string = { 9cc8ec30388cc71f42ee6366372dde28f6cb7c60e887c4d62ff58a702914cfb9e271882215ccfe5148ab2c3cca6b2108d88e0ec6647d7f7e97f0495997039ead }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
