
rule m2377_1ad9d6c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1ad9d6c9c4000b12"
     cluster="m2377.1ad9d6c9c4000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['115fbc4d6d93623451bba95e9afe28ef','2786295bfc4a3ceee3e2af1048726683','fca2b23fc2befe397702b6b804b09204']"

   strings:
      $hex_string = { 43454d454e555f44524f505f414c4c4f575f5749445448333634203d2066616c73653b0a0d66756e6374696f6e20737461727447616c6c6572792829207b0a09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
