
rule m2321_4b94a690db9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b94a690db9b0912"
     cluster="m2321.4b94a690db9b0912"
     cluster_size="12"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor shiz zusy"
     md5_hashes="['07ff557dc244c775b41aac558d9f95fd','193a8cf8722370f3c4bd56969f71d557','eec866f390f07db86b67902875248285']"

   strings:
      $hex_string = { c0fa0405fd5511fbc234255d5683a1bd7c1cd1579807e03ea4122c319a914a8eefb5f8b439f645b89f272e42b36038294ca8c9a3c4b6636152cc21ad9c1a85f4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
