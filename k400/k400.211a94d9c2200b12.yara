
rule k400_211a94d9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.211a94d9c2200b12"
     cluster="k400.211a94d9c2200b12"
     cluster_size="962"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tdss zusy pondfull"
     md5_hashes="['0082e694ab0d78b542b5754ed8f8704a','00bfdfff0d18d5f75442a0a5dbbb4a33','037e8cdcca161dacc5a14373c22f8bf0']"

   strings:
      $hex_string = { 6f66742d636f6d3a61736d2e763122206d616e696665737456657273696f6e3d22312e30223e0d0a3c6d735f61736d76333a7472757374496e666f20786d6c6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
