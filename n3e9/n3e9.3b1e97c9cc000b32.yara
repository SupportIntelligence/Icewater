
rule n3e9_3b1e97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1e97c9cc000b32"
     cluster="n3e9.3b1e97c9cc000b32"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious bilky"
     md5_hashes="['02bac43955ea5748d4f8a94e301f70ff','1156e6803a9d4b4345d867dda522ce54','5cfa6fc85f93a636ea2746976f9dff5f']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
