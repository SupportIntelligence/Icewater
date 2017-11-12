
rule m3e9_339d2cc9c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.339d2cc9c0000932"
     cluster="m3e9.339d2cc9c0000932"
     cluster_size="122"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy popureb"
     md5_hashes="['00f9b65f1393d6fc2bfc9181da5e2591','0368be75c8978c24521d21e2a20baf20','51a7291b214f28ac68ed15a2bc03edad']"

   strings:
      $hex_string = { 0002000000848440000800000058844000090000002c8440000a0000000884400010000000dc83400011000000ac8340001200000088834000130000005c8340 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
