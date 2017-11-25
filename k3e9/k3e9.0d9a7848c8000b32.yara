
rule k3e9_0d9a7848c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0d9a7848c8000b32"
     cluster="k3e9.0d9a7848c8000b32"
     cluster_size="1045"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dropped lanman laqma"
     md5_hashes="['0081b92d70259b007a0e13574c284c7d','00bd6957a3ff9fc7f06cc665fde212f2','08b647f1126efdb33173edb13f01f9fe']"

   strings:
      $hex_string = { f07415578bc26a04995ff7ff5f85d274076a04582bc203c8f644240c0275048d4c71028bc15ec3558bec83ec185333db395d0856570f84470100008b7d103bfb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
