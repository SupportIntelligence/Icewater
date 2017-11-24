
rule n2321_1b7a52a2852948f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1b7a52a2852948f2"
     cluster="n2321.1b7a52a2852948f2"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installbrain brantall bundler"
     md5_hashes="['16ce9205ca4338f6181ac3ea78c0b103','1ffe3bdf04758f6d9bd710e513467915','fcf77eee746ecda86eb80e0d112602f0']"

   strings:
      $hex_string = { 257d2f0b14ff26c6d13c9458dbf8ecd40dfa3e74fd23c163dcf6b14f9901bfe0e5d5471b849ffeb63d172d09245c786916ba8abd71a67aaa861127c26c2be420 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
