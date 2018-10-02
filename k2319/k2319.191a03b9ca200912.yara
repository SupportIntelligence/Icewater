
rule k2319_191a03b9ca200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.191a03b9ca200912"
     cluster="k2319.191a03b9ca200912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9546b1be7e15d5558d8046b0327b517687e28e24','9186fb6ee819df75b4d708911925e701699ab9fc','fa56d4e5c58fc3648c53c3640bf1975b50bb1ae9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.191a03b9ca200912"

   strings:
      $hex_string = { 54354c273a225a222c27643370273a2866756e6374696f6e28297b766172204d3d66756e6374696f6e28592c43297b76617220563d43262831312e313645323e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
