
rule p3f1_3932c19dea211912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f1.3932c19dea211912"
     cluster="p3f1.3932c19dea211912"
     cluster_size="4"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware skymobi androidos"
     md5_hashes="['3ca252f85fe8407bb984d5bbe3b2eaa3','49d80c985c0b1a43e60d1364ed31c5d2','e70287a10a4efbafe58e9e6fd77b8e7e']"

   strings:
      $hex_string = { e3edf5a403f26f13b86435a6f3ee0ee6206db5abefb20ff796dd7455e077b13dce3b9758d85f05f64acce8c13e2e70165ad55c5388235b9961d31cb73ab05d69 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
