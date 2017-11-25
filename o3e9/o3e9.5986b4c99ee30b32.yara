
rule o3e9_5986b4c99ee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5986b4c99ee30b32"
     cluster="o3e9.5986b4c99ee30b32"
     cluster_size="206"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor dealply malicious"
     md5_hashes="['00783452cb41c5be26b711907bdc2626','00c1059aa09f267506e1790bc4ae3646','103e98e543783feb3e16910f185866b6']"

   strings:
      $hex_string = { 250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005004d00 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
