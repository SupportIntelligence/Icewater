
rule k2319_6912e318cd22f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6912e318cd22f112"
     cluster="k2319.6912e318cd22f112"
     cluster_size="45"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loic flooder html"
     md5_hashes="['01ddd6774c7c12f0ec23fb8709c7299c','0285a79636160ce70b5554cc598bc0f8','39381c1542e821dca34ebb1c3f13465e']"

   strings:
      $hex_string = { 2e636f6d2f696d616765733f713d74626e3a414e643947635467303977335932784858537645624774776332664f3435537538366a5a48692d75625033705155 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
