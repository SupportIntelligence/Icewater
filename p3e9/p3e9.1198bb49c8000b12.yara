
rule p3e9_1198bb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.1198bb49c8000b12"
     cluster="p3e9.1198bb49c8000b12"
     cluster_size="82"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock pxbii nabucur"
     md5_hashes="['0b80d08a18b5b85d721ea7f2ef13dd75','0b9f54d048a283684a986e1b83337286','a55de21276de09b7f1682721586925cd']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
