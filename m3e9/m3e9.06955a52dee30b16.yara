
rule m3e9_06955a52dee30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.06955a52dee30b16"
     cluster="m3e9.06955a52dee30b16"
     cluster_size="584"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna vobfus barys"
     md5_hashes="['019b4854df932fdc31e3dcbee737b1ef','02099eb26ef8674132cde4310dc563df','0f5b4f31b186565ef2c078b22a6cb478']"

   strings:
      $hex_string = { f401fccbfe64e0fe4913001c800c006cecfe6cf0fe9e2afdc748ff0b460004002f48ff1c3d130016f38402eb390a05000800fd6b60fffde608001803000b6360 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
