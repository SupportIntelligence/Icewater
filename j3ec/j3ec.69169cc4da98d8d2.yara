
rule j3ec_69169cc4da98d8d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.69169cc4da98d8d2"
     cluster="j3ec.69169cc4da98d8d2"
     cluster_size="43"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut advml malicious"
     md5_hashes="['0bc5e53a74f387abf97c6d6f58ce5522','0c4e748d326bd21c0f64e6a6aa6b0b4c','63ea0a9b9e0ef440d6afef278c3eb7cd']"

   strings:
      $hex_string = { 45088b483c03c80fb7411453560fb7710633d2578d44081885f6761b8b7d0c8b480c3bf972098b580803d93bfb720a4283c0283bd672e833c05f5e5b5dc3cccc }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
