
rule k2321_23d4ecedb6664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.23d4ecedb6664aba"
     cluster="k2321.23d4ecedb6664aba"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['06e83c1472035bc17fbd629b36c743da','070b97b1be9f24def15367543092011a','fc93cfced5b66d019eec477f9f83066d']"

   strings:
      $hex_string = { 7661e2d05f72b4ac291397473a0e99aee7bf50a8c514c93093276ac1f779da1cad58cd48b6b717326b2f64fe0f0a6de567464c21ac05081da3867c4bd1334fcb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
