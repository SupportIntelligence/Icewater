
rule k3ec_211c1299c2200916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.211c1299c2200916"
     cluster="k3ec.211c1299c2200916"
     cluster_size="13"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms hacktool kmsactivator"
     md5_hashes="['1a1f1bda02c031e84d4f80c85242c994','41b50cf9d1a52e84fb4ff86d40fbe50d','fdfb702523f0b35d662853ff99edd002']"

   strings:
      $hex_string = { e82eb6c490aadb61a5181359ac6b7c1110f4d05ba3769cf927311dcf64fa6e172fb7078abb9b5e943406d432f74cd877a2b0423e530b4ebe8ecc3db99d2a4f55 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
