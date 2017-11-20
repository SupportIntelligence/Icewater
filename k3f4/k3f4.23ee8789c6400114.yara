
rule k3f4_23ee8789c6400114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.23ee8789c6400114"
     cluster="k3f4.23ee8789c6400114"
     cluster_size="200"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor agxy"
     md5_hashes="['003c7e52e9f29004b2176d64f96ebd29','01d13430a3f5ae668881ae3529275b9d','11af9f1d7fb2f22dd84f2b4671dcac2c']"

   strings:
      $hex_string = { 546f426f6f6c65616e0053797374656d2e57696e646f77732e466f726d73004170706c69636174696f6e006765745f45786563757461626c6550617468004279 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
