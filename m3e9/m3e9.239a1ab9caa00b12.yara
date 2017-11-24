
rule m3e9_239a1ab9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.239a1ab9caa00b12"
     cluster="m3e9.239a1ab9caa00b12"
     cluster_size="31"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yakes ransom symmi"
     md5_hashes="['01d4719bb4ba84a8ddbd23e65a38b0ae','085dbf42e0db284f9c37fc1e018fcb2a','97adf810290c9642dd25ccd05972a126']"

   strings:
      $hex_string = { 47021d01ee78a8af3a61765ea2018a6c302ff5d1966f0b9ad3cd3c0db31345855c08cc7b8f197f48918d31dcd77d5fadfc86e3e28260b2fd7cc5e86e9f3646c7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
