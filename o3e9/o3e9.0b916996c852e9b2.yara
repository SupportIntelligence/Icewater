
rule o3e9_0b916996c852e9b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b916996c852e9b2"
     cluster="o3e9.0b916996c852e9b2"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious heuristic"
     md5_hashes="['06ef5ca30bab0b789b3b046ccf000d80','1d9e280eeec8cf9d993d967d4fcdc75c','f14874cf9df181a43aa8af8de333ddb8']"

   strings:
      $hex_string = { ce9a835e493fd6da51a02912abccdcc40a391dfcae1b591f4a3e80c115f24777bd25faade0c7f987d5b6549ccbeb92f12b30715c130c646c1a6a3d46323a0285 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
