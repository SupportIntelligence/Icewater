
rule n231d_1398eadedee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.1398eadedee31912"
     cluster="n231d.1398eadedee31912"
     cluster_size="157"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddad hiddenads"
     md5_hashes="['777b7d839ad43f5d42ff20e9c5ac7bb300a3a2d9','db27dbcae33cbf47f151ff7302fa86fd38f81cab','0f1d541aa6d413ec98c9cf93388654bff85ddaf7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.1398eadedee31912"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
