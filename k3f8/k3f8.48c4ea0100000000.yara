
rule k3f8_48c4ea0100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.48c4ea0100000000"
     cluster="k3f8.48c4ea0100000000"
     cluster_size="34"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit androidos hacktool"
     md5_hashes="['00418ec857d7237f369a0a8aeca149f7','0090fbdf7e3031be112a5351346f0c53','5b70c28e15d3eb2c3dbbe6a20b8d293d']"

   strings:
      $hex_string = { 696f6e2e424f4f545f434f4d504c455445440006617070656e6400096172726179636f70790001620001630012636865636b436c69656e745472757374656400 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
