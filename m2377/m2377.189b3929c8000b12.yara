
rule m2377_189b3929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.189b3929c8000b12"
     cluster="m2377.189b3929c8000b12"
     cluster_size="16"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0ff4a09fc068e3f212672f8fa8dfb787','46e9aaf74c4c2ff6c65adc1790646a8f','fd8c3f5d86a3fa1c4e95d637e8fbec17']"

   strings:
      $hex_string = { ff39e72b4b7551deb68fe2c26892ccc405da4d1774861e97ca24cd99211f12e4d38d4c50151307948bc0e044a8bae67bcd3c03c7c3405df6069c63d6fc9814ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
