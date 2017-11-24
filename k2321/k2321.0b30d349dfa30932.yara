
rule k2321_0b30d349dfa30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b30d349dfa30932"
     cluster="k2321.0b30d349dfa30932"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jtlp kryptik hupigon"
     md5_hashes="['08e094a93938fcd04754c8cedd39987d','3721dcb1777516a9fe62207309c9205a','e6ed3aa2cd66e82aa03c3a023ee895e6']"

   strings:
      $hex_string = { d4124b3ac3927871e54e7b6dcba277cde64fd74ac9e94e019a9c0397b0140b092351561f73f3553d635187c58e8c2a0dcadaa6855718f1af9bb8f45efae36f43 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
