
rule k3ec_619e7a41c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.619e7a41c8000932"
     cluster="k3ec.619e7a41c8000932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut malicious virtob"
     md5_hashes="['00b711d24b6d37623275b706850964ae','07c21d820b99610f48d04852c1183f6d','d95182467d95bbeb8084104d1e24ec52']"

   strings:
      $hex_string = { 312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c212d2d20436f7079726967687420286329204d6963 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
