
rule m2321_3b1db299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b1db299c2200b12"
     cluster="m2321.3b1db299c2200b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['05f8381f08539593aac896e8bf42a7ef','221f8c02b7a99cf54237a5f32c13c3dc','f08d41f2dd7e80c3e25e9ce6190da6f6']"

   strings:
      $hex_string = { d1bcad0436c51f0a491e574b7298b20676cf529514d8b6552a91cb05686cf4f2fbb387440b45f39c6f8f3c39654a4fbed6755d60f718459b3ec9795b567b469f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
