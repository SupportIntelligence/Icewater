
rule m2321_291f6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291f6848c0000b12"
     cluster="m2321.291f6848c0000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif agentwdcr fixflo"
     md5_hashes="['43d2f7fd41f3b434fee9414111639f75','546a9b9a3758681393330eb4e6f4e634','99592fcf8410f99745cdae1782d1acee']"

   strings:
      $hex_string = { d5b87a154c6147431e9f89c11a459767038f09792fb9868a8768a68404e6d193e9565ebe9c11faf9ba0d249bc8d19471d7ef82758b1481cda08e3b17c4f8ae5d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
