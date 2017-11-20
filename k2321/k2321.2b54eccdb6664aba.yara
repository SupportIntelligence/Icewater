
rule k2321_2b54eccdb6664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b54eccdb6664aba"
     cluster="k2321.2b54eccdb6664aba"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['0dab05d98b8d343268fa51648f3f95b2','368b392de359e9968ee0d14b3d011ce4','cf2d1769724dac5cb8285802a5d87147']"

   strings:
      $hex_string = { 8c32fd9881903d88ef2bff635de98fc934e5ea10833cfca7cfe48ad3b0a17d862815d28e17a3bb5611372e2f6f446e41e6941929455326c430a6e8c352ae1f1b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
