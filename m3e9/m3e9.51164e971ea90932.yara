
rule m3e9_51164e971ea90932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51164e971ea90932"
     cluster="m3e9.51164e971ea90932"
     cluster_size="69"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys raideloz"
     md5_hashes="['056a7176999ac00cf93346645dacca29','0bf02891162d55404c9f4fbfb11b6e97','a6c239d4f6aa41110a0690f2bda43fab']"

   strings:
      $hex_string = { fad0fd63c99fe73f953ff5feb3be475047b6da5efc53aded884c04d15bb2496c7a58833973269b8a8f10e59d514267bfaa8c89033644cbeb486bb1742fa35499 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
