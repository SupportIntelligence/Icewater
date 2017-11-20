
rule h3ed_2a554086c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=h3ed.2a554086c2210b32"
     cluster="h3ed.2a554086c2210b32"
     cluster_size="128"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorv fraudtool malicious"
     md5_hashes="['0066c7823e453ed3979d73f6b543e68e','05850dbd18b5e4a72c608ad5e5521ae7','275cf149913f89354b8532bdad3f0ad6']"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a240000000000000066bad1a222dbbff1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
