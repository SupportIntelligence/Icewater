
rule m3e9_329d2cc9c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.329d2cc9c0000932"
     cluster="m3e9.329d2cc9c0000932"
     cluster_size="148"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy popureb"
     md5_hashes="['00fd9c9fae524245d447022eea765b14','018e40d238886dd2be9856b249b3aeed','59bd028c6d910acd9dd56cd9336d57a9']"

   strings:
      $hex_string = { 0002000000848440000800000058844000090000002c8440000a0000000884400010000000dc83400011000000ac8340001200000088834000130000005c8340 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
