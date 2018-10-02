
rule n3f8_119992e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.119992e9c8000b12"
     cluster="n3f8.119992e9c8000b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos bankbot adlibrary"
     md5_hashes="['d2a32de0da205f1180f040ca43397a57cbe5316e','ab1a54c52c3baba5d2f11b805f878c62798289e5','cad941d7bbca6684c7bae1cba7d337a2845f2544']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.119992e9c8000b12"

   strings:
      $hex_string = { 73244e6f74466f756e64457863657074696f6e3b00254c616e64726f69642f636f6e74656e742f7265732f5265736f7572636573245468656d653b001f4c616e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
