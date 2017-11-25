
rule k3f4_21346a4dc0010912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.21346a4dc0010912"
     cluster="k3f4.21346a4dc0010912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['169167d872c3bce0339f1d802fce3449','c13fd471eb3ad0e01be7cd093feef44e','d2bcf5ee6d9b6951bfc7d46be8e7803c']"

   strings:
      $hex_string = { 000400efbbbf3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
