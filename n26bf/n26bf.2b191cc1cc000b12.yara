
rule n26bf_2b191cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.2b191cc1cc000b12"
     cluster="n26bf.2b191cc1cc000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androm boilod malicious"
     md5_hashes="['c19489f8b74cd43c9c1b02a6da2bedbda23b1f25','05acfe1ac0083bf94c1403647ad76a3b13b870b4','d48e6b1d03c63ab98beb32f29985c53d09e66271']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.2b191cc1cc000b12"

   strings:
      $hex_string = { 706f3f00000a0b000714fe0116fe01131211122d08141311ddaf030000076f4000000ad48d260000010c070816088e696f4100000a26284200000a0f01284300 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
