
rule n2319_199dea48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.199dea48c0000912"
     cluster="n2319.199dea48c0000912"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ramnit html script"
     md5_hashes="['d5945c4655639b15205343e17a450fc567fe4c56','3093e153fdf1914bb175d76a1e9a3b984d4f4531','1aa5c021b7ea4bb249970ed73bd5fef0a0f6ddb6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.199dea48c0000912"

   strings:
      $hex_string = { 696e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
