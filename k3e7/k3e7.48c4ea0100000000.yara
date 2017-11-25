
rule k3e7_48c4ea0100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.48c4ea0100000000"
     cluster="k3e7.48c4ea0100000000"
     cluster_size="73"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit androidos hacktool"
     md5_hashes="['020277f5f8788112a4c0dd462ce01d28','064d3e3994cbccc8c582d66c37592f5f','349da095c31bebb1c85562db8e85bfab']"

   strings:
      $hex_string = { 696f6e2e424f4f545f434f4d504c455445440006617070656e6400096172726179636f70790001620001630012636865636b436c69656e745472757374656400 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
