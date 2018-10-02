
rule k2319_521a96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.521a96b9c8800b12"
     cluster="k2319.521a96b9c8800b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['beb6c60cf953786c7a7ba4644e3f507726be6e4c','7db8539185f09a3b178609de02061c5433d066e0','b4b88580fe44c31dbcc9b8e00245ec5576158972']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.521a96b9c8800b12"

   strings:
      $hex_string = { 646f773b666f7228766172204f367020696e207538503670297b6966284f36702e6c656e6774683d3d3d2828302e2c30783336293e31322e313045313f37333a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
