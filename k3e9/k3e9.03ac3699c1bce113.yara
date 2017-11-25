
rule k3e9_03ac3699c1bce113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.03ac3699c1bce113"
     cluster="k3e9.03ac3699c1bce113"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="peed qukart backdoor"
     md5_hashes="['05926d410d76b5e2bfb4b09f3edccadb','89757398157ef6a0bb544bfd64887ce8','dd3efc94276c5f565a52190df2823f39']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
