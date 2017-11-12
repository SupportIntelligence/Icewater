
rule k3e9_091ef3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091ef3e9c8000b12"
     cluster="k3e9.091ef3e9c8000b12"
     cluster_size="252"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['0e541001c8c74d32dc66cf303e8feb05','0ff646bb0f9dd37ef5faebdf219ccff6','3bf946e2825e042919ce091f92ead627']"

   strings:
      $hex_string = { 7475616c50726f7465637400001902496e697469616c697a65437269746963616c53656374696f6e0077014765744d6f64756c6548616e646c65410000060248 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
