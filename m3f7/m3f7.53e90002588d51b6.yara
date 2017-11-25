
rule m3f7_53e90002588d51b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.53e90002588d51b6"
     cluster="m3f7.53e90002588d51b6"
     cluster_size="19"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00e78922f74ab48ed3e6f393aed19f5b','07c29af226d9af87e58d7fa790a6134d','ce9e69bdd341f379697579edbb8a5e5e']"

   strings:
      $hex_string = { a79a70928d12305debc594f662f9a13f3fe98f8aa8603fb3995e5930a5b645768bc0cb79455e444887cc3be14291e3c5de58465f20c1ab7f15433f4f01a6cc17 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
