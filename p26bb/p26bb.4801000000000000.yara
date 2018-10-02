
rule p26bb_4801000000000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.4801000000000000"
     cluster="p26bb.4801000000000000"
     cluster_size="1022"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious tofsee attribute"
     md5_hashes="['fa8007521e3737da168352f1e9c7fd56b14f9223','5333c12330d89b2c26de12b5a4ce91cc4b209a6d','ac6a3cbc1562c76864320264beb266067e27c73a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.4801000000000000"

   strings:
      $hex_string = { d34e98bc8fc3ad45eda0fffff146fc0fd6add0479b926fc291872622c97f226c891a120b1884cde5e203487aaae4b334020b64be2b54a1727bb438b7cba7d5de }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
