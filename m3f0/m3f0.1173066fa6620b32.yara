
rule m3f0_1173066fa6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.1173066fa6620b32"
     cluster="m3f0.1173066fa6620b32"
     cluster_size="775"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="advml attribute kaazar"
     md5_hashes="['001cf15b78ce2c921ffa3873798a0201','008a6d32b4b9ebaea9fb9b1ac01e06bf','0634efa967cf5ca50bfe65891c185517']"

   strings:
      $hex_string = { c15bab83b716dfc5a5ebf86a7a0b6d9e6f42f53c1f8c618a323f69a0cdc39db17924c920e83d44f1035dd4e6d1709b47310f52f0b9ea0d7c2b98e3b606f9be41 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
