
rule j3e9_1649682618aa4ada
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.1649682618aa4ada"
     cluster="j3e9.1649682618aa4ada"
     cluster_size="486"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre zbot generickd"
     md5_hashes="['0249da68f16239c7c1986e43ec44a885','0296857a6cb5fd7bba123b6484cdee3e','1f0265b69fca054ec01e3c4f58a0074d']"

   strings:
      $hex_string = { c6ff08147dd2def45bee2f331f4bebe1657b2c395b778faf454d134fa49bdfcc12b6b70a86388016856e5b295da6caa7a4c3da524eb3bb5f0dd4fe029e72f915 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
