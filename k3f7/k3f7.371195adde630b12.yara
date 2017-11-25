
rule k3f7_371195adde630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.371195adde630b12"
     cluster="k3f7.371195adde630b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['4eac74cc581e4f34d07f2c0dc4ff04a6','50351bcfc26e65e8f6391524f2cb0cb4','d6dffa1c9d9b723bbcca47c5e6e03cff']"

   strings:
      $hex_string = { 3e3c696d67207372633d22696d616765732f706978656c5f7472616e732e6769662220626f726465723d22302220616c743d22222077696474683d2231303025 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
