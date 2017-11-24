
rule n2321_01983929c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.01983929c0000b12"
     cluster="n2321.01983929c0000b12"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide downloaderguide bscope"
     md5_hashes="['03f310303ed86c925d5982f1446c310e','1c225f643e928159130de1530341f1c6','ed4a1acf0cde7bd73fafec6706ff0d2c']"

   strings:
      $hex_string = { 42b9c78436aaed87cbdf30e996a975273b617059938e518f85987bb0ef6b7f681f56ea29ebe4e8699afa48da8938beba014e2ace08f1b17805d83219e66e2b8c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
