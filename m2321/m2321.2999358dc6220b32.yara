
rule m2321_2999358dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2999358dc6220b32"
     cluster="m2321.2999358dc6220b32"
     cluster_size="34"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['07ed3fcca278ab3e36bb2de3230de74c','1391b5a9845eead17e320122f1d16a86','79beaa912ca8864517480a37cdeb446d']"

   strings:
      $hex_string = { d38b73c4db1865ed9dc356d0abb228f7046c60018f6af8d6383070e65f8abcae49a8583d799f74175c33c666a490e94007e4eedac0bdd5f292956e5e1bb7dc2c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
