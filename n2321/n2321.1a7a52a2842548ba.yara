
rule n2321_1a7a52a2842548ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1a7a52a2842548ba"
     cluster="n2321.1a7a52a2842548ba"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installbrain brantall bundler"
     md5_hashes="['03c31d09b14f6338b28d5983394af28c','155a5acf4589449ea1dde02916658fc1','c7bea65fcead5a0dc06a717ce7c49589']"

   strings:
      $hex_string = { 257d2f0b14ff26c6d13c9458dbf8ecd40dfa3e74fd23c163dcf6b14f9901bfe0e5d5471b849ffeb63d172d09245c786916ba8abd71a67aaa861127c26c2be420 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
