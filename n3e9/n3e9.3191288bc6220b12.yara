
rule n3e9_3191288bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3191288bc6220b12"
     cluster="n3e9.3191288bc6220b12"
     cluster_size="81"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nymaim injector malicious"
     md5_hashes="['03d0e282f8c18fc5fa2b79ffb438943c','0658771fa2694cdd710e6744a8dfb949','4aa1f8f4d2846e0ae3c106a40c7ca616']"

   strings:
      $hex_string = { 02ded34f9677e18208f88ce69c59bfe80136d1459799e3049e0ed460a7e725203fbdcc211716f127aea3c36a3b1419188941f5c10a0c4a5266acb313f3b20fb8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
