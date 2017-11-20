
rule m2321_5b9e8cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b9e8cc1cc000b12"
     cluster="m2321.5b9e8cc1cc000b12"
     cluster_size="43"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mailru unwanted mail"
     md5_hashes="['04157ef83f6264006fb7bcfccc5754c6','0a9ce789ce263a3075ace4421de8a231','5b47bd1e5913843bf678ea8caea2091b']"

   strings:
      $hex_string = { e0c303cc6401859d2f7503f0c2e39f4322723d04957aefbd47d87d57fe106ba2b28d20d61c07c51bd5b0dae95faaf92d4b2ae50bdf1227383e5c374eee312e14 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
