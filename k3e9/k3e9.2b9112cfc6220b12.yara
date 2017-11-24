
rule k3e9_2b9112cfc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b9112cfc6220b12"
     cluster="k3e9.2b9112cfc6220b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader dmid"
     md5_hashes="['1511847e54ee256cd93fb455c701eb22','355d04faae55adca4d6d25528a8d8fe9','c4fcd44ff25b6abfac7ebfa86eb24d14']"

   strings:
      $hex_string = { 0366aea5ec37623b77f02848b2d026235d66ac6e12a47ca65bdcd7f46e071cc2c9a26c817a04e52941a9e395e78dc115c77872ea54a0eed1052d750b16e8cf33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
