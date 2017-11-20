
rule m3e9_13b65cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b65cc1c8000912"
     cluster="m3e9.13b65cc1c8000912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus autorun jorik"
     md5_hashes="['0c26c4dc2886bfac5099365857916050','c402edf74cd41dc27fcff56c8127101e','e01395e370cafed8e00c7fca791975c5']"

   strings:
      $hex_string = { 81dec6ccd8cccbd7cc3b3b2e282e2d2927262d676cb8bfc3b86870514c4b100dbcdbf8f5f5f8f9ce5941000000197d7d81dee5cedaf2daf0f5ba665e46463d5f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
