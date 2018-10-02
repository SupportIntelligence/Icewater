
rule k3f8_1a630e669cfb1110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.1a630e669cfb1110"
     cluster="k3f8.1a630e669cfb1110"
     cluster_size="307"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw smsspy androidos"
     md5_hashes="['aa4ad893cc364eb606a272d464ba450badcdc751','a9b6fe9c572a0eae8bcd5c3e5781fb2a5a1de1b7','af8c42742bfe17e5bed4a000fff39ec0c819f6af']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.1a630e669cfb1110"

   strings:
      $hex_string = { 00402d5f313233343536373839306162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
