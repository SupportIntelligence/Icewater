
rule m3e9_3115c8de993f4b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3115c8de993f4b10"
     cluster="m3e9.3115c8de993f4b10"
     cluster_size="83"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi wbna"
     md5_hashes="['0a9d6e5f4386cfa35e8fc45d70abceca','0ab3dad20c8cb085d7e17776ef17184f','6611c577d488ed8548449d46d680fb36']"

   strings:
      $hex_string = { 4b1ec07546d6a678ddbb8cd3a070bd6f3ca84414b56138cea479e9e8baedfbc7e5d9aace9a6cb55b2bae4810c67442e3ac84f7d7bbfccdbedfa99fb1807b9771 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
