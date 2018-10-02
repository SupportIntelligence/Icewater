
rule pfc8_31324ac2d96e6912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.31324ac2d96e6912"
     cluster="pfc8.31324ac2d96e6912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp adlibrary adpop"
     md5_hashes="['923776a18b127b3332e8bafe4b9ab1d679695f76','d434e73a4e465018031df27bffcad0786771ec7b','dd54d21ea71a5b9563d252737627e271cf5b8b76']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.31324ac2d96e6912"

   strings:
      $hex_string = { 9621aa1d97415a761e9c4db1949d88804483e83129935cb5c50ac20943b3ccdf7aa07465d0e43201c959b42749fc2da8250e58e6c73d50c6ae1bfd18d68e1f37 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
