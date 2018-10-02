
rule i2329_3a1fb9a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2329.3a1fb9a1c2000b32"
     cluster="i2329.3a1fb9a1c2000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dangerousobject multi phishing"
     md5_hashes="['b354e4430a652e2f690100f3833581bfca0b7586','2f64a6e9968a4edee0214430390f7d8d5a0fcba1','86f4300e6d2fdfccfe4b7045ee700ed9ed48d343']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2329.3a1fb9a1c2000b32"

   strings:
      $hex_string = { 255044462d312e330a312030206f626a0a3c3c202f54797065202f436174616c6f670a2f4f75746c696e65732032203020520a2f506167657320332030205220 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
