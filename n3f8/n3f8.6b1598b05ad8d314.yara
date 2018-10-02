
rule n3f8_6b1598b05ad8d314
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6b1598b05ad8d314"
     cluster="n3f8.6b1598b05ad8d314"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos gugi"
     md5_hashes="['9737fce6649b8940b930713341cea0626595bc93','2e9a8d1d1541d3b6f108216e303efd23c8e6bd2c','40d2c39f8cf4b30143c393b248d829456ce258bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6b1598b05ad8d314"

   strings:
      $hex_string = { 74566965773b000d4c6173742d4d6f646966696564000e4c61796f75745265732e6a617661001d4c636f6d2f627567736e61672f616e64726f69642f41707044 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
