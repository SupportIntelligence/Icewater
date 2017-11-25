
rule m2321_393158b4dfa30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.393158b4dfa30932"
     cluster="m2321.393158b4dfa30932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cripack yakes pariham"
     md5_hashes="['29831e4af0b51e68d8f8900dcd101537','49631a43c98372d547f162c312591cf1','ead258c69cfa8598a74d1ae719799ddc']"

   strings:
      $hex_string = { 38534b757db74d8c9137ec111e668710df6128a1af55a3c8e98b03ef21bc92b46ad46467dc9b7c45c7bd760c8da5629aff1448a9ddc9ea171fad0ab6fcdbb996 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
