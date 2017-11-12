
rule m3e9_138f17a142000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.138f17a142000b12"
     cluster="m3e9.138f17a142000b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1f32ccf4ab4c48d71a525eb82454fc0a','2bf5547be70523a3b6831b0019c46581','a4c34efa826f30c3c6d681b72095015c']"

   strings:
      $hex_string = { 0101012a9589414948242b2312151b300101013a947a3e5d4e3f4035110e14380101013b91584c5c5b46474517131f2e010101438f55546c5a4d534b1d1e282e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
