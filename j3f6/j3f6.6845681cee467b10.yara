
rule j3f6_6845681cee467b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f6.6845681cee467b10"
     cluster="j3f6.6845681cee467b10"
     cluster_size="175"
     filetype = "data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis nsismultidropper"
     md5_hashes="['05d154ed7229b4cff9e62c0d1045b6b1','075fb2d4d346b4bc13a0fa5d19c00f83','1b56b18e2d1fb512a59e928cda0c2502']"

   strings:
      $hex_string = { 496e7374616c6c2053797374656d2076322e343600ff82802053657475700043616e27742077726974653a2000436f756c64206e6f742066696e642073796d62 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
