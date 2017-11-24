
rule m3e9_7b148e16ccbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7b148e16ccbb0b12"
     cluster="m3e9.7b148e16ccbb0b12"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality vobfus wbna"
     md5_hashes="['0ce8c91e28da37d54b7ae511c7ee5ee5','1296851b1d9fd301b6ed64c5f806fc22','aa7467d814fd119a05684ea17380b870']"

   strings:
      $hex_string = { 45a4508d45b4508d45c4506a03e8dae3feff83c410c38d4ddce816e4feffc38b45d88b4de064890d000000005f5e5bc9c20400558bec83ec18684634400064a1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
