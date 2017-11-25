
rule k400_211ab9d9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.211ab9d9c2200b16"
     cluster="k400.211ab9d9c2200b16"
     cluster_size="82"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tdss zusy autorun"
     md5_hashes="['02a4fc55b22c581c4d989282b67d0f32','0312c0b5af16f09584a1ba2f9f2a66c3','49b16dd74db9c81fd3d7d5add479f3b1']"

   strings:
      $hex_string = { 6f66742d636f6d3a61736d2e763122206d616e696665737456657273696f6e3d22312e30223e0d0a3c6d735f61736d76333a7472757374496e666f20786d6c6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
