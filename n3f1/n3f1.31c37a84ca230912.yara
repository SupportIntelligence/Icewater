
rule n3f1_31c37a84ca230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.31c37a84ca230912"
     cluster="n3f1.31c37a84ca230912"
     cluster_size="407"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos andr smsreg"
     md5_hashes="['002be9069f0a16e161752b20c6fec48a','00395b545109d65ac0fc9fd6ca4af51e','07fd8796f008eee81637caccaa272bfe']"

   strings:
      $hex_string = { 76907294c86917e4b431ccc19c36e674886f4bbd3dfc8a18c5102ef664828ba92a6135ad84aecf6a488344c7555037dca59621d6a22c59af917858120f2bf5d9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
