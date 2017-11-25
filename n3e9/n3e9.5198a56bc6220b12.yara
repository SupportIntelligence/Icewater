
rule n3e9_5198a56bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5198a56bc6220b12"
     cluster="n3e9.5198a56bc6220b12"
     cluster_size="71"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loadmoney cobra cryptor"
     md5_hashes="['0b0dd70b9cb629cdfb652392cf9d029d','0e14269a1e6ff798fde7beee987c30cc','3e11181b665a12a2d200c1b0de978595']"

   strings:
      $hex_string = { 41646d696e6973747261746f72222075694163636573733d2266616c7365223e3c2f726571756573746564457865637574696f6e4c6576656c3e0a3c2f726571 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
