
rule m26bb_116a3c4148000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.116a3c4148000916"
     cluster="m26bb.116a3c4148000916"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious adinstall"
     md5_hashes="['9cf76bef34ada0872d80da6e35eb468f045a0eef','51265fdccba1a58820b2718b5021aea5439a5440','9a8667ff03a13c8d35e37eb66111f008707352ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.116a3c4148000916"

   strings:
      $hex_string = { 9592730072c74b59e6b953e02e3cf88fa630639a0b253129c9ce9d5a933e9c45ebec778058086e4f892710ac39ba9119a5224dd0d4d2c0992b0548e1c3b865f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
