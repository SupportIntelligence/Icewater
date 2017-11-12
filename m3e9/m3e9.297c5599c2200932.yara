
rule m3e9_297c5599c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c5599c2200932"
     cluster="m3e9.297c5599c2200932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['2b8e098536142594fdec25ac0e3ebaa9','398e3e986eac9c88c694dedcd0ea06e8','39d3955dee410d87d85e90bfed3a4032']"

   strings:
      $hex_string = { b8a86d8b989fa39082766250353dd8de37dbc84a0dfd040404040869dfdfc4d3ddc1c1bfc0c0d2d2d1cfcebbbbcdbab9cccca87e989ca1a69283626387b3daa9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
