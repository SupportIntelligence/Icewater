
rule m2319_039a14b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.039a14b9c8800b12"
     cluster="m2319.039a14b9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script embtfc"
     md5_hashes="['36fdb4f953ee9f82501010b7ac715e3496a5916e','5c19c7e1dfc7d3a1fa75dc9796f940890f2be532','53dd618e285728d05e5b0dd3bb23336c5d91b735']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.039a14b9c8800b12"

   strings:
      $hex_string = { 20683620613a686f7665727b636f6c6f723a233232327d2e64656661756c742d7374796c6520696e7075745b747970653d227375626d6974225d2c2e64656661 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
