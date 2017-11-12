
rule n3e9_4b16b2463ee16eb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b16b2463ee16eb2"
     cluster="n3e9.4b16b2463ee16eb2"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler optimuminstaller"
     md5_hashes="['09761965e8a4a7eb8fc0eeedd22a6986','0f4dc55a870ae5da0385184ebd64f373','6be8e3f05734971fefb2369e9ce4fc0c']"

   strings:
      $hex_string = { f4eeeeeef2f2f2e3e3e3cdcdcdfffffffefefe0000ffffffefefefc7c7c7edededf2f2f2f2f2f2eeeeeeefefeff2f2f2efefefdededed1d1d1fcfcfcffffff00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
