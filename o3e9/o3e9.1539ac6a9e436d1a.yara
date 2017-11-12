
rule o3e9_1539ac6a9e436d1a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1539ac6a9e436d1a"
     cluster="o3e9.1539ac6a9e436d1a"
     cluster_size="374"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['010cfcde819443f340b4c6bc4425b23f','01a38f90b984dd06a0fb2e5f3a159910','09f8268d27851b23861b339bc1c49e18']"

   strings:
      $hex_string = { 062ad20dd46edba9979a608c6feafeaf5d122cb4f5193f7b0463deec35bcdceda2eaa4ffe4c963f85aba591a74df60b31279c90d3ce34e22cab67c06f2269275 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
