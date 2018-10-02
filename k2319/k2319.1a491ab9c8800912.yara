
rule k2319_1a491ab9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a491ab9c8800912"
     cluster="k2319.1a491ab9c8800912"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['216ebd33f5019ee5ed5ff663d6dbe4961cb5ec4e','7f55fe2be04e85ebbc48df2a0d3a9b9aab1c75ca','81e6ce43c7bfc25feda886916be4b198000cdaf5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a491ab9c8800912"

   strings:
      $hex_string = { 646f773b666f7228766172206a335620696e207a30693356297b6966286a33562e6c656e6774683d3d3d2828307843462c3538293e31322e3f2838392e354531 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
