
rule m3e9_297c6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c6a48c0000932"
     cluster="m3e9.297c6a48c0000932"
     cluster_size="328"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['02fc38e2881aef7fe1d54d939b6e2a4c','046b4bebacf518fc3a05ddbb0c414bab','3b62e9febd3f8e692abfea66c8106778']"

   strings:
      $hex_string = { b8a86d8b989fa39082766250353dd8de37dbc84a0dfd040404040869dfdfc4d3ddc1c1bfc0c0d2d2d1cfcebbbbcdbab9cccca87e989ca1a69283626387b3daa9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
