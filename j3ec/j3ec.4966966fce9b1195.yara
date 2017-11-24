
rule j3ec_4966966fce9b1195
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.4966966fce9b1195"
     cluster="j3ec.4966966fce9b1195"
     cluster_size="319"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aqvmvuji infector"
     md5_hashes="['00cf16b6c3e676018b05665dc1c37eac','00e96ede508a0b25f17894d95e1965ee','0bb6dc2380d34b0e25ca90ed24d7ced7']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
