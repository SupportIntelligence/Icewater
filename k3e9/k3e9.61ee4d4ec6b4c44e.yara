
rule k3e9_61ee4d4ec6b4c44e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d4ec6b4c44e"
     cluster="k3e9.61ee4d4ec6b4c44e"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['8b0ec11467d480f121fb0b3187e92a8d','b700f28c97fe28bbeda37bbeeb3c4e54','cbb9f3ad46e6cec10b092c20dff0b26a']"

   strings:
      $hex_string = { 0aca97008f40270fc74d30178d6e4c3edd6f4e41eb634235f0725043f7bc7958ffa16c52fe573727f8644131f6654232f23e2114d83c2214b145261a48442b22 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
