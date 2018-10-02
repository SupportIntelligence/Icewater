
rule n231d_3398d49adee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3398d49adee31912"
     cluster="n231d.3398d49adee31912"
     cluster_size="151"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['d767562d3df50cecf39cff0ba5015c82fb3a8cc0','27038758128ed9109b5c4343628c656e032657fd','f805c36286ddd46b2139ef91822d89feda203b53']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3398d49adee31912"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
