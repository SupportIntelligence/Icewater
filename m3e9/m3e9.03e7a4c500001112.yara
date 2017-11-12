
rule m3e9_03e7a4c500001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.03e7a4c500001112"
     cluster="m3e9.03e7a4c500001112"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik malicious"
     md5_hashes="['9aa4128c6c570887a56999c007a3ff4d','9eda4bc13008211f2dba8252e4489e8f','ee3425d8fe0f41ef21fe1c15aeaa3455']"

   strings:
      $hex_string = { 2020203c72657175657374656450726976696c656765733e20202020203c726571756573746564457865637574696f6e4c6576656c20206c6576656c3d226173 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
