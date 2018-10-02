
rule n231d_29191299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.29191299c2200b12"
     cluster="n231d.29191299c2200b12"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar banker"
     md5_hashes="['96c0bad9847d513d5e98acd3357d609fc85f66e8','4604c10e14b1b03a9f80983680ba26992bfbaa7c','902f0cdea0b0b2bf5e4881118303543ab7bf84e1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.29191299c2200b12"

   strings:
      $hex_string = { bf86d5822d6adc2259e8d180e7e4cc17f8f2529030067092a5cb0dfd04b0d89ad4e2c5f4999829a643af9627ca40c3bea9445e01973f68bbb70b188b076dd7b6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
