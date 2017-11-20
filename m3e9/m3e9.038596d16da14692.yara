
rule m3e9_038596d16da14692
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.038596d16da14692"
     cluster="m3e9.038596d16da14692"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun juched"
     md5_hashes="['a2bd37bcd0f634937b367fd9848f6296','a42fb9adb0bebba2a8ccb022be0a8782','f84ff7787ff741361e8acbf32a16ec94']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495b01041 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
