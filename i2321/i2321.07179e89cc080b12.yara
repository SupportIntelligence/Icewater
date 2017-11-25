
rule i2321_07179e89cc080b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.07179e89cc080b12"
     cluster="i2321.07179e89cc080b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['17000d836d48b595737ea45107a6f9a7','2c5e00b8322b170f94f62c015c9d4e25','ffafedd29980b91877a3c06a891724a7']"

   strings:
      $hex_string = { 8c6569ed85acbf7a4cdb7d0d7722f71b6b2ab69c8b3dcdc5f4e27f39d650d815ef8762adbd217daffd74f0ee9efc36e6f7c4d3f0f2a6d8505cf3b6187b6d53ec }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
