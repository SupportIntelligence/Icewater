
rule n231d_299a9099c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.299a9099c2200b32"
     cluster="n231d.299a9099c2200b32"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker hqwar"
     md5_hashes="['5c19969b2c9e44c6ff80f19ee58782a26e44211a','8821493813fc5bc8d7d04b9a3118068e5f03fc03','5269b673a653b335bd6f1ccae4d3f0b94421a618']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.299a9099c2200b32"

   strings:
      $hex_string = { 7ad7813a7ba8899d248e205294e902968fc8a318f0b6413fbd137e0b16a4fd731cc2503dbfc1172c2d3497a91a039a780c7400d8dd04be66d448103111336ee2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
