
rule k3ec_39957ce392c20b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.39957ce392c20b12"
     cluster="k3ec.39957ce392c20b12"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="attribute malicious engine"
     md5_hashes="['0699a47d3813b3f32f365fabc042c9fd','5d1b524ccfbd3b7cab3844b4770b4c36','fae50532c9540cff5219c50c91dc93f5']"

   strings:
      $hex_string = { 2f005f5f766372745f4765744d6f64756c6548616e646c65570031005f5f766372745f4c6f61644c69627261727945785700564352554e54494d45313430442e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
