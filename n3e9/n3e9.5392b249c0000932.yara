
rule n3e9_5392b249c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5392b249c0000932"
     cluster="n3e9.5392b249c0000932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus diple chinky"
     md5_hashes="['556a2264e11edae3f3e77276a1b33842','63713bcb58b1ffc09f3e11b82efa89b6','ee2ffb5e51a722a03e7b32105703c256']"

   strings:
      $hex_string = { a4508d45b4506a04e857c8fdff83c4148d4580506a00e8cbc7fdffc38d4ddce816c8fdffc38b4de064890d000000005f5e5bc9c20800558bec83ec1868e64240 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
