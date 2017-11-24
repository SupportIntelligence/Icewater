
rule k3e9_13158a50d8a2f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13158a50d8a2f916"
     cluster="k3e9.13158a50d8a2f916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['5c1a911815a0c700b4138d39c2730b98','758b52223b9623835ec98865f222d6ca','ce1604bf115ae58791300685fee040b2']"

   strings:
      $hex_string = { 649d625d896b96c02c78e60e55c96d56b2c8a5eea48419b566f67526422798499980501aedc42707080f94126c1473bf10f152323585d69749eb9af9380065df }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
