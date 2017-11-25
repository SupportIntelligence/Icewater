
rule m3e9_297c5cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c5cc1cc000932"
     cluster="m3e9.297c5cc1cc000932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00277ea07ddcc8183e1c4f996e0550ac','17adccf5cc222b206571f0e1bc3fb66e','cc377602cf51c2113da5290decbf59b4']"

   strings:
      $hex_string = { b8a86d8b989fa39082766250353dd8de37dbc84a0dfd040404040869dfdfc4d3ddc1c1bfc0c0d2d2d1cfcebbbbcdbab9cccca87e989ca1a69283626387b3daa9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
