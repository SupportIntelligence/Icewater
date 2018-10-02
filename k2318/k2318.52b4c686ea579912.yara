
rule k2318_52b4c686ea579912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52b4c686ea579912"
     cluster="k2318.52b4c686ea579912"
     cluster_size="356"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['c47b11d5701015100d3b153ac3eb5657dd54a174','3a6e1708122648a6f97f37db7016a219850d8414','34aa2302aca751b3b284663cc60501b8b902bc61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52b4c686ea579912"

   strings:
      $hex_string = { e8eae0ba20f1f3f2f2bae2eee3ee20b3ede3b3e1f3e2e0ededff20696e20766974726f20b3e7eef4e5f0ece5edf2b3e22043595031c0322c2032c0362c2032d1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
