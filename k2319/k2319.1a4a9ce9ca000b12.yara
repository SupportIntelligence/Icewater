
rule k2319_1a4a9ce9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a4a9ce9ca000b12"
     cluster="k2319.1a4a9ce9ca000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9209ffcb0677268d525b8b109e05be8fa8c28c86','a95d72299412db2ac668f5024c9c3b854d911669','a306354b62797ed7c5476d3a82dcc51cfa0403d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a4a9ce9ca000b12"

   strings:
      $hex_string = { 545b795d213d3d756e646566696e6564297b72657475726e20545b795d3b7d76617220563d283131342e3e3d2839302c33392e293f28352e353445322c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
