
rule k3e9_13159250d8a2f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13159250d8a2f916"
     cluster="k3e9.13159250d8a2f916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['045573df0c7c0b726a18340735f1ef26','2ff60e97251dfec52b1e77288bfcc296','9c005352eee46dec181fb373f64c2c17']"

   strings:
      $hex_string = { 0384074a09368ab95f887829999a42ebcba475cd7c1c80b26f70242e64221231ab93f85cfc4c9674271b9b45c94d04bed5d454eadc90a939225dac3b1365dd79 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
