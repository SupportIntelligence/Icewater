
rule i2321_1672c4cdc6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.1672c4cdc6210b32"
     cluster="i2321.1672c4cdc6210b32"
     cluster_size="30"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="padodor backdoor symmi"
     md5_hashes="['071954f52ca6ef3b46fcf0e7532d9525','0992194d8daaa62a7f52e9d526aca9e8','7d41d2c3b9408cb71c8eb2ecafdba419']"

   strings:
      $hex_string = { 59c9bc6da58c3d5775928def57334f14fee454a189ecbbd8b810db835dac3f88e5d83223d79ce9f8b0a453b16a292dca4e287917be1d5311584312a89bd45681 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
