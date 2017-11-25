
rule k3e9_51bb4526994f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51bb4526994f4912"
     cluster="k3e9.51bb4526994f4912"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['235f44183cb8420b8dcbb4e034ce079b','536b2ab42cdf4cbddb1a195643efc0a0','f94d3fc9c3bb27bb07c2aee384855f52']"

   strings:
      $hex_string = { 312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c212d2d20436f7079726967687420286329204d6963 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
