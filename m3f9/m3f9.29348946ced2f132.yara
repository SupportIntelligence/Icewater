
rule m3f9_29348946ced2f132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.29348946ced2f132"
     cluster="m3f9.29348946ced2f132"
     cluster_size="322"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor kazy"
     md5_hashes="['03464aa2045249e435655b5f353ef4aa','05c705594cb406c447f3e998bd174b9e','488b52f7361c665d0e024bc95ff231bf']"

   strings:
      $hex_string = { f47d3a453bba8d2a4b09f093f6e3988a30dfb90eced2bf3eb113419f5bc3e47568cb7b38ea247086d16722f34d6c4310a0ede179fbff76230025bc2fda959d1f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
