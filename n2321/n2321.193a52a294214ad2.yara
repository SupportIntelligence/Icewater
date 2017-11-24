
rule n2321_193a52a294214ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.193a52a294214ad2"
     cluster="n2321.193a52a294214ad2"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installbrain brantall bundler"
     md5_hashes="['129b80a2b4d955c31e98dd2af0e5f3ab','1be5e99cd7d57c0b6aac5b1fedbd47a9','f587600b0da1a204651da40d18ff6a7f']"

   strings:
      $hex_string = { 257d2f0b14ff26c6d13c9458dbf8ecd40dfa3e74fd23c163dcf6b14f9901bfe0e5d5471b849ffeb63d172d09245c786916ba8abd71a67aaa861127c26c2be420 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
