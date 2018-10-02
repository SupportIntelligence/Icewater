
rule pfc8_491a3135cbab9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.491a3135cbab9932"
     cluster="pfc8.491a3135cbab9932"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="apptrack riskware andr"
     md5_hashes="['106e6a50561677eea0ebc868dc48b06ba7123f2e','10209f5702f7a5893c60033a07e07fdab193b257','5414b9f87c686b3e4a26dd60590ada7581498bc2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.491a3135cbab9932"

   strings:
      $hex_string = { c3fbc5db94158c49109b9f1d738bc04c165738c2479c2ef6c765670d064f2d3ada30833f75dcb2956cd0b681722c31ea518f1107a337d6c8a50468b526b4c96e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
