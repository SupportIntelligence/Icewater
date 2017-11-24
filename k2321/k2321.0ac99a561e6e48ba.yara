
rule k2321_0ac99a561e6e48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ac99a561e6e48ba"
     cluster="k2321.0ac99a561e6e48ba"
     cluster_size="51"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['00d72d5d3c650e220cbf14ecbf45dec1','132e3e1fdcf986dc79e3a1d95ab468af','6b459052926b31b522c99860b819c5af']"

   strings:
      $hex_string = { 72c53813972f58a6a34384e7f99def03c6f2c33d8874f454f17950220fdc62452b446e118fde245c08a19827179652852578d22794db149e6829a0ac200d6090 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
