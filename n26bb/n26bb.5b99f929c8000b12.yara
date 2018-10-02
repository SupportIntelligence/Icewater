
rule n26bb_5b99f929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5b99f929c8000b12"
     cluster="n26bb.5b99f929c8000b12"
     cluster_size="7308"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="autoit azden bizd"
     md5_hashes="['2d291c1440f98c9ce7522528affc94f89e3dcdd8','d9a83e1dec4893637312fd8c40de52375bdf79cc','21bac00b7a23e3ca98d6c70fbd5ce5fbd50fb6aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5b99f929c8000b12"

   strings:
      $hex_string = { 1012a51f3050d94228230c6109758263b9d0147ee82c683e04bae4608d9e39d877d779316c99bb1d8334539203c90bf0c3fdbd19dc3a1633ef8e98a78149bf65 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
