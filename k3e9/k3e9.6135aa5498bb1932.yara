
rule k3e9_6135aa5498bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6135aa5498bb1932"
     cluster="k3e9.6135aa5498bb1932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['cfa26356d24f8a23d90a22bb610a3f21','d65367454394d8f595a88c456d7f10fe','ed1e5d72b65959d9f284d8f05e71f847']"

   strings:
      $hex_string = { 312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c212d2d20436f7079726967687420286329204d6963 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
