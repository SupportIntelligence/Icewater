
rule n231d_299d1299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.299d1299c2200b12"
     cluster="n231d.299d1299c2200b12"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos guerrilla lezok"
     md5_hashes="['16ed8ee0b87327f31b5d1aeff4fa138a309b058f','4525e6fe665ea630a7b38d400063e43491d48a51','f95a338a15ef6ecba2c4b3811f6a4a2dbfcd3f3a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.299d1299c2200b12"

   strings:
      $hex_string = { bf86d5822d6adc2259e8d180e7e4cc17f8f2529030067092a5cb0dfd04b0d89ad4e2c5f4999829a643af9627ca40c3bea9445e01973f68bbb70b188b076dd7b6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
