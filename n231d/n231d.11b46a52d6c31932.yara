
rule n231d_11b46a52d6c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.11b46a52d6c31932"
     cluster="n231d.11b46a52d6c31932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['1d40e255300f41ede81a2e13633bbd1db6ce2c40','16171b7cb116732482342bbb353b0a2bb4db86ba','c14b6a34774caedde572139670da909009066418']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.11b46a52d6c31932"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
