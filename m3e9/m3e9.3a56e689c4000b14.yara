
rule m3e9_3a56e689c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a56e689c4000b14"
     cluster="m3e9.3a56e689c4000b14"
     cluster_size="107"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['016e375476e46e6afd78f6dcb7e4d474','0a1ad15b06b9c27143fb921bf8b09395','98a18817db768e3c57229c981fdfe431']"

   strings:
      $hex_string = { 5940a53a1db4cbe01fb647e7f5c29bddc7af665dcd9ebb4a285045f10e87a6312751737483a2fcd57f0dc7206cdb1737b2e17072bade92b3fe424fa70699419f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
