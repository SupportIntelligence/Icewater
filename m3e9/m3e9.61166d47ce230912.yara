
rule m3e9_61166d47ce230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61166d47ce230912"
     cluster="m3e9.61166d47ce230912"
     cluster_size="263"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['01c05a85ab80606810b099b6620220cc','03abc9c0638d9379b5f9f72c03999473','2be908567c916611efda84e1f81beb14']"

   strings:
      $hex_string = { 9bdad9d8dfdedddcd3d2d1d0d7d6d5d4cbcac9c8cfcecdccc3c2c1faf9f8fffefdfcf3f2f1f0f7f6f5f4ebeae9e8efeeedece3e2e1abaaa9a8afaeadaca3a2b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
