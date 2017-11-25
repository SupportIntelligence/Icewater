
rule m3e9_5c146126c1bae332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c146126c1bae332"
     cluster="m3e9.5c146126c1bae332"
     cluster_size="80"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jorik vobfus chinky"
     md5_hashes="['021af38d815274b25b9a872606a07722','07c6d37965efe519242ac8fade3da771','9db77229ee72e3977a70c83400f70036']"

   strings:
      $hex_string = { b9d8dbd9ccc3c0b77cae969d98021279d8f3f6f3f6ddce4a220000000c2e2e2b53c0ccccdbf3dddb3d0a290a292a2e2f4277b6d9ccbebd7a7daf96999910076a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
