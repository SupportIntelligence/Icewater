
rule n26bf_331486b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.331486b9c2200b12"
     cluster="n26bf.331486b9c2200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik malicious attribute"
     md5_hashes="['10b38bfaf0d3d2fae48f6f79816a14aa545a58e6','6f76700298ecd202ad63a81b12df4502accbe7bf','105712b4de1d23ddaf8f28c3f323a27c527b7371']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.331486b9c2200b12"

   strings:
      $hex_string = { af7d1797e56c56c68088b0a100872628aa729b70e6183582cfe2f9ba8a52503baf711e0f9f0167d6dce6e8b87bd8492aa8e189088b1107cbdbf7efbde4b674d3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
