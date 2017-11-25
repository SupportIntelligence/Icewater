
rule m3e9_3a552575c8b79b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a552575c8b79b14"
     cluster="m3e9.3a552575c8b79b14"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['01a9e4c9f263a1ade7d0a054f12b225e','02d1313bd4fd89d5aadf9c35ff98d427','dd847bc8740b933159541e190b3649c1']"

   strings:
      $hex_string = { 96b4702bc77c81fe1a208b5d467632fda45b3f6268b82a8c86425527da9bdf3d7a1145045299a23ad3bcd4d59402159784d125ccc416186972c3aa9f1340c25f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
