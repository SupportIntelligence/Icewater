
rule j3f6_6865681cee467b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f6.6865681cee467b10"
     cluster="j3f6.6865681cee467b10"
     cluster_size="26"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis hzdg"
     md5_hashes="['16cf837f76b9f50df0dec8a34bd54da2','3c8ad7dc1329dfc3de3ca08af9848e66','8fdf1b91f630e62ebc23660b69c57919']"

   strings:
      $hex_string = { 496e7374616c6c2053797374656d2076322e343600ff82802053657475700043616e27742077726974653a2000436f756c64206e6f742066696e642073796d62 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
