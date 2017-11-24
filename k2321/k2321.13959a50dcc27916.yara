
rule k2321_13959a50dcc27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13959a50dcc27916"
     cluster="k2321.13959a50dcc27916"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['4207b0b6409b2aa909badb463b75424a','47f17c4092dce6d6ffc4e0097449ae50','dae74da8bbf4ae49abaa68a80872bc67']"

   strings:
      $hex_string = { 8dee51a33bf42d11353ad5ed15da7a78a6f9f80e6d69cf328ceaa75767131be0c599250412d0866563565ea8b02a3d292b7be1bd99f594f6ce6c620dbc31b344 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
