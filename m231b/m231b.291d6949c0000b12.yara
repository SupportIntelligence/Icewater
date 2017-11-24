
rule m231b_291d6949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.291d6949c0000b12"
     cluster="m231b.291d6949c0000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clickjack"
     md5_hashes="['0a18d8501eef326769be8bf686bc6750','6497e342502bdf35485b2c2b74ee406a','b198c97af59b3d0e8de9273fe7fa3af1']"

   strings:
      $hex_string = { 273e0a2f2f3c215b43444154415b0a66756e6374696f6e2073686f7770616765436f756e74286a736f6e297b766172207468697355726c3d686f6d655f706167 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
