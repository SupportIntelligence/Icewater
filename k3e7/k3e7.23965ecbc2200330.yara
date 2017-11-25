
rule k3e7_23965ecbc2200330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.23965ecbc2200330"
     cluster="k3e7.23965ecbc2200330"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="linkury toolbar classic"
     md5_hashes="['017ea0a376051313f47d4ebeba560fa5','048dff7e5d9aaeda8483f46b42c9b7bd','e44297921be869d322fa7944ddfe5183']"

   strings:
      $hex_string = { 37033d018c054101b50565003703860035066b0186020000003c4d6f64756c653e00756f755f415053465265632e65786500446576496447656e005570646174 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
