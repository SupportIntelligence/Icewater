
rule m3ea_33356a5eda927b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ea.33356a5eda927b12"
     cluster="m3ea.33356a5eda927b12"
     cluster_size="2014"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware gxoyy androidos"
     md5_hashes="['0005aa1e362a7c4f6b6a92608b6bba06','001578fe1ae266e3cfb0dc3a9ca9ab6c','01588a2ac1db09d8a8f6d56e9575097b']"

   strings:
      $hex_string = { 5ecbd719a845be0374ab40d2bc963f647833fe4eefd9b81230fc9f4db22c26de8cb36c6e47a4e42af94a875342883b2352f285dc9981edf07ee40aec7162757b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
