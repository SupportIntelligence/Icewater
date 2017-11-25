
rule m3e9_5054d2d3da3b8910
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5054d2d3da3b8910"
     cluster="m3e9.5054d2d3da3b8910"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef wbna"
     md5_hashes="['09524513c37f9b16d1de7e06e193fc63','098a67ed5391581741adc0aca855136f','a969febe7d90de34601827c641dc80ed']"

   strings:
      $hex_string = { a46f9e12c7201c1de30464f38c014d5afaad19f8570d60fc25cab2dcf713c518b799e7785c5e6f80a586529cb0f5684f2cc4ff0065e63869508a7cd4334a7463 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
