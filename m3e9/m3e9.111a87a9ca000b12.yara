
rule m3e9_111a87a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.111a87a9ca000b12"
     cluster="m3e9.111a87a9ca000b12"
     cluster_size="28"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus autorun vbobfus"
     md5_hashes="['0462f930a267673c49f6b4c3bff94ba5','06d63ec5ebac68dc6c641287e3cdb042','c1d2c3458b01174fb8d42c9d2b2de1a6']"

   strings:
      $hex_string = { 81dec6ccd8cccbd7cc3b3b2e282e2d2927262d676cb8bfc3b86870514c4b100dbcdbf8f5f5f8f9ce5941000000197d7d81dee5cedaf2daf0f5ba665e46463d5f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
