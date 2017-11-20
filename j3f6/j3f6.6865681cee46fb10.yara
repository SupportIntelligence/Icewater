
rule j3f6_6865681cee46fb10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f6.6865681cee46fb10"
     cluster="j3f6.6865681cee46fb10"
     cluster_size="32"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis nsismultidropper"
     md5_hashes="['0cf5720b5c3f08e63818e48c8430efee','0eeaf2693f0344c26935affe30b8737f','aa02c55c408ebba968bba004ce573ad2']"

   strings:
      $hex_string = { 496e7374616c6c2053797374656d2076322e343600ff82802053657475700043616e27742077726974653a2000436f756c64206e6f742066696e642073796d62 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
