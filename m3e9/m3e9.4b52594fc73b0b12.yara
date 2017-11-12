
rule m3e9_4b52594fc73b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b52594fc73b0b12"
     cluster="m3e9.4b52594fc73b0b12"
     cluster_size="321"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="coinminer zusy maener"
     md5_hashes="['004870c8de1db74ff0fd6e66cf19e04c','01bbcfb363f50f1ca09842af87190404','222a6581d1abdfaae45ead918b729af5']"

   strings:
      $hex_string = { f44c9a7c57a44ae71956bce187eb3332d211aec900c04fb68820c7329ec48bbcd21185d400105a1f8304c5de59a313e834488a2aba7f1d777d76993c35496b51 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
