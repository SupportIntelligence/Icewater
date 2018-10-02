
rule k2319_3816a3adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3816a3adc6220b12"
     cluster="k2319.3816a3adc6220b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['84757ce20bd62e413df81528af13bbc24d83dbb2','9eabe004d5be9c5bc1a917ccac6d3f40871b66ea','186f92de75d05a27fe0eb81d30d8a7ba11d3fa45']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3816a3adc6220b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b525d3b7d76617220533d28283078382c31312e293c3d2831332e383845322c37352e293f28362e2c3078636339653264 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
