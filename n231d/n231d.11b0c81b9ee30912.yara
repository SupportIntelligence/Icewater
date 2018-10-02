
rule n231d_11b0c81b9ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.11b0c81b9ee30912"
     cluster="n231d.11b0c81b9ee30912"
     cluster_size="189"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddad hiddenads"
     md5_hashes="['edf617602ec2a3854956201455491c6ab1380620','38e2471f86b3259c76c372204e11e257c29294e2','d2d29aad10cd94c9938d07bd075013d6a0649728']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.11b0c81b9ee30912"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
