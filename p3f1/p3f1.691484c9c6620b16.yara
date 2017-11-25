
rule p3f1_691484c9c6620b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f1.691484c9c6620b16"
     cluster="p3f1.691484c9c6620b16"
     cluster_size="3"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos generickd"
     md5_hashes="['0535dfd1cdb34bd5195af720bf034d03','2b942bd16e3e65347acaec794eac3d07','a84f74a3e9597957b087076ca034ac69']"

   strings:
      $hex_string = { e8bce10a9b05f790a139533851e73529bfbb282fd111879922b6f37ccaba3be443702a6b79419418b3d6258bd99dbe858aec424d766146965d4b5055912e3498 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
