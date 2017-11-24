
rule m2321_0194a007ea608932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0194a007ea608932"
     cluster="m2321.0194a007ea608932"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['22b0a4617db8c3f85bd91a459792b4cb','43aa41d442f2434b1f383ce2b80b53ae','fe48aedc655f5e06667a261f4f7fe08c']"

   strings:
      $hex_string = { 59b27421c075be2d03f79208d8cfa3a1d052d96ecbc840460d0681414bb36dfee65a075e353d8f42ea30874af383166b0fccdd4518fa0b2b9dab96f2c151ca47 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
