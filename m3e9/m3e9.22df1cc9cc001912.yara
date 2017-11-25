
rule m3e9_22df1cc9cc001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.22df1cc9cc001912"
     cluster="m3e9.22df1cc9cc001912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob patched"
     md5_hashes="['004f265c2c7e6a4dd258104f44085b18','12304b0a2084c9a68bf6c5b7640a5240','cfe54ab5e397824afb2001e6adceac27']"

   strings:
      $hex_string = { b8a86d8b989fa39082766250353dd8de37dbc84a0dfd040404040869dfdfc4d3ddc1c1bfc0c0d2d2d1cfcebbbbcdbab9cccca87e989ca1a69283626387b3daa9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
