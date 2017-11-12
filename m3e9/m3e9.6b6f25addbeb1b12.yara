
rule m3e9_6b6f25addbeb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f25addbeb1b12"
     cluster="m3e9.6b6f25addbeb1b12"
     cluster_size="607"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['00cfb929c006240bca5d16f4f84352ec','021f0e420a23d36a631eac30daab6f07','1461065f28f8edb666a8dd7aee4ac59c']"

   strings:
      $hex_string = { 0529fb5c8997d1c95a1315badb95fded15f97e54b099b49fdd5bc548df6055e4f6243ecd57cb7648d5d62ac623f447f57a671087f071fd00f834bee4c0fc3c81 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
