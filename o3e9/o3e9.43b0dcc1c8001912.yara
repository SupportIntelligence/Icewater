
rule o3e9_43b0dcc1c8001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0dcc1c8001912"
     cluster="o3e9.43b0dcc1c8001912"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['0a6cd825af0e1bb50d10a9ccad41e8f4','3975e3ad533d2883f8df984ef6aa997e','d62d91d0a5e6d5201607a5f599995dc5']"

   strings:
      $hex_string = { 12b717d13635ca8ad7209d0f9c4d7d7109e521384e4c0c2401d45251c804b9e9d32d15d89f564784686a1d9b31a17e3703995cb446768083ec941ec6a9f4b5aa }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
