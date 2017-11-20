
rule i2321_1672c4c2c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.1672c4c2c2210b32"
     cluster="i2321.1672c4c2c2210b32"
     cluster_size="13"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="padodor backdoor symmi"
     md5_hashes="['1104dc1cd11899c0713b5506da20defe','35296a80d93188f9d121f493e0b960be','fc5af81d0472f99392b225a3aa74f935']"

   strings:
      $hex_string = { 59c9bc6da58c3d5775928def57334f14fee454a189ecbbd8b810db835dac3f88e5d83223d79ce9f8b0a453b16a292dca4e287917be1d5311584312a89bd45681 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
