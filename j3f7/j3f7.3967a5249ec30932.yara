
rule j3f7_3967a5249ec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.3967a5249ec30932"
     cluster="j3f7.3967a5249ec30932"
     cluster_size="21"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['33de97471bfd34990bd493947118b702','34b6f93ec2694f53509b21bd000d9e9c','dfcd479a82d1fad472234f8150f035b2']"

   strings:
      $hex_string = { 726765743d225f626c616e6b223e3c2f613e0a3c2f6469763e0a3c212d2d436f707065726d696e652050686f746f2047616c6c65727920312e342e3320287374 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
