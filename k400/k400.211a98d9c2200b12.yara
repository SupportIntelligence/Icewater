
rule k400_211a98d9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.211a98d9c2200b12"
     cluster="k400.211a98d9c2200b12"
     cluster_size="214"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tdss zusy pondfull"
     md5_hashes="['03662d4904e6635d57d9696ff6942d5a','050bb4d0f4c262770853f2df8fc0d339','2404f4f39c27873cfdf7a4463f502bf3']"

   strings:
      $hex_string = { 6f66742d636f6d3a61736d2e763122206d616e696665737456657273696f6e3d22312e30223e0d0a3c6d735f61736d76333a7472757374496e666f20786d6c6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
