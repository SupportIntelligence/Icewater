
rule n26bb_09989cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.09989cc9cc000b12"
     cluster="n26bb.09989cc9cc000b12"
     cluster_size="92"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic bxib unwanted"
     md5_hashes="['fe7b9046a86bbd2cae50cab7f9fb2ec7ed9460e8','4071c68fa669940ab3544a77a4924d05289093ef','a7e0c8b11f0febdebdeb8ac108cde9333647e0ec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.09989cc9cc000b12"

   strings:
      $hex_string = { 7d4721523c1fb05dbf3149f86701e7dbbbd8bc33404b720cf56481be2fb9242e1af7741e5e954588cf200a5632b6853f076d8750920830c0b3988311da508fd3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
