
rule m3e9_149279596ce54647
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.149279596ce54647"
     cluster="m3e9.149279596ce54647"
     cluster_size="242"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['01885a96d39a22a59729c5849994e786','049692b8908bf4cd94b928edeec38b07','232a8e7a81c0c2fddbc78689ad841d60']"

   strings:
      $hex_string = { ee20582223f8934c120ce26c881b9295fe1f6856962d0f8f84f23554bb3473a7bd187ea0d7bc029c2beb014df30a8b6a1ab9c707701e16ed4aebe0cefbaf1451 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
