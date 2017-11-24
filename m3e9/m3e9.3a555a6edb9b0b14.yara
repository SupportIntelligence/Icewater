
rule m3e9_3a555a6edb9b0b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a555a6edb9b0b14"
     cluster="m3e9.3a555a6edb9b0b14"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['577a7eb7a7b839e80610aa096ea0df9c','aeb50efe495843cb6e050143ac9a722d','cfbbc8d3fa7cec40c0765b58b5e0ea43']"

   strings:
      $hex_string = { 12b717d13635ca8ad7209d0f9c4d7d7109e521384e4c0c2401d45251c804b9e9d32d15d89f564784686a1d9b31a17e3703995cb446768083ec941ec6a9f4b5aa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
