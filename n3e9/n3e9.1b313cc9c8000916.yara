
rule n3e9_1b313cc9c8000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b313cc9c8000916"
     cluster="n3e9.1b313cc9c8000916"
     cluster_size="81"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel pykse"
     md5_hashes="['104b4b952cda9186af26226cb02e5ab8','166d3160e853dccf1707e7817391aa5c','a351d3b7005f78aa68d1db7e975abd6e']"

   strings:
      $hex_string = { f004c8f768c1d85596a3dc5bb0599163247e10aa8547a937fd780cbcd6effa0ef55a67379b2e734c922b9aa1a077863adabf510a8d50d138c93e9416122a9f5f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
