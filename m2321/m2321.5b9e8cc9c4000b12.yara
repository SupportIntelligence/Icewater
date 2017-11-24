
rule m2321_5b9e8cc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b9e8cc9c4000b12"
     cluster="m2321.5b9e8cc9c4000b12"
     cluster_size="32"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unwanted mail mailru"
     md5_hashes="['08c6fec66074f5b6fd758554a0eb8216','0c7e436aa8550f8d2d209566e8534299','ab07faa0d38cb2504d3a7eac7319b19d']"

   strings:
      $hex_string = { e0c303cc6401859d2f7503f0c2e39f4322723d04957aefbd47d87d57fe106ba2b28d20d61c07c51bd5b0dae95faaf92d4b2ae50bdf1227383e5c374eee312e14 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
