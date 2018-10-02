
rule n2319_32984484ce210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.32984484ce210b12"
     cluster="n2319.32984484ce210b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['65369274be01a8f0934cecbd1fe655ee3b2c4127','885aeba9e29b7d0c777d2458a08bf9c7bd0531e4','38481d63689a431e96afac78b5fe07702eae6870']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.32984484ce210b12"

   strings:
      $hex_string = { 617265617c627574746f6e2f692c563d2f5c5c283f215c5c292f672c573d7b49443a6e65772052656745787028225e2328222b462b222922292c434c4153533a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
