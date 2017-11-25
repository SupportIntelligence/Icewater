
rule m3e9_19228d4d86221132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.19228d4d86221132"
     cluster="m3e9.19228d4d86221132"
     cluster_size="16"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys agnn"
     md5_hashes="['04516ec9aab6070e1b74900549b3d43a','095e46748d65c0aeb21c4198c129d657','debad1f0ec6583a9c5632b9401803aed']"

   strings:
      $hex_string = { 010c194a220d1212101345445260627761875b4546638e9191bbcacabc9dbbe0edfbfffcfcfbfbfaf4a7000000f4fcfc03131f1e1d1d1d1e43475472737c7e8a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
