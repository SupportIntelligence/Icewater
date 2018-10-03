
rule n26d7_3914cce3e9691b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.3914cce3e9691b12"
     cluster="n26d7.3914cce3e9691b12"
     cluster_size="61"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor zvuzona malicious"
     md5_hashes="['f724eab4c55ac9996e48e4b58df37c7878e8e508','1fe0f5d16538f5e6ae09c335c307856a82eb4924','127d2d7360f0c6cc307708948c27b278ec609db7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.3914cce3e9691b12"

   strings:
      $hex_string = { 24b5206441008d421883c11883781408578b781072028b00508b4110e88fb7fffff7d81bc05f405e5dc383f8037518db4104d94208dae9dfe0f6c4440f8bb200 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
