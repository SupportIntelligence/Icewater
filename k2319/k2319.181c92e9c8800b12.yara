
rule k2319_181c92e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181c92e9c8800b12"
     cluster="k2319.181c92e9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['df1ed34363d257a0272745d7643a265eedbaf7a8','3a888d1d9667c0b720255b0408a02a0d8885db23','44375de95d00613aa306fdaafda85e5077415ec7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181c92e9c8800b12"

   strings:
      $hex_string = { 6b7d3b666f72287661722075384820696e2063395a3848297b6966287538482e6c656e6774683d3d3d282831302e343145322c3078314638293c30783231333f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
