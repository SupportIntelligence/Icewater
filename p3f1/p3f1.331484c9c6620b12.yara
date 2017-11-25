
rule p3f1_331484c9c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f1.331484c9c6620b12"
     cluster="p3f1.331484c9c6620b12"
     cluster_size="13"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware androidos generickd"
     md5_hashes="['00b00fba0fc9f87a454e585af5147ee9','338e4520c7bcc0aa8da764dcb4e84cce','fb3a4687572b4cf65bab7776a9b3ea47']"

   strings:
      $hex_string = { e8bce10a9b05f790a139533851e73529bfbb282fd111879922b6f37ccaba3be443702a6b79419418b3d6258bd99dbe858aec424d766146965d4b5055912e3498 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
