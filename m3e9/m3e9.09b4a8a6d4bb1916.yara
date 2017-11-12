
rule m3e9_09b4a8a6d4bb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.09b4a8a6d4bb1916"
     cluster="m3e9.09b4a8a6d4bb1916"
     cluster_size="1080"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys lethic shipup"
     md5_hashes="['008aacf5c6614b44eda14b66a7d62ecb','01c20867b9e22cd5fc86f898d1edbd84','0ac286dab94011d61a87081fcd1c4f12']"

   strings:
      $hex_string = { cbc2bfeb9e36cd8837c96c7b0139068ec577ba9d081132bca3ee54521bef8ab2c7f1b1e53302ba3a33469d31966539995d944799cee1bb2e8216a1da582fcf2a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
