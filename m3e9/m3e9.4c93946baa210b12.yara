
rule m3e9_4c93946baa210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4c93946baa210b12"
     cluster="m3e9.4c93946baa210b12"
     cluster_size="6586"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bitcoinminer generickd autoit"
     md5_hashes="['00007af9b37aaf63ba81985857ba4767','0002a09bc15d9f8df302f0f0166397b5','0073fa827789bb34b6e6ea4dfb4e0085']"

   strings:
      $hex_string = { 0a0e03a2ac955f4b9e562a09a63d91158edd35835207853ee366e447db620c39cbb9d6fef2376736f546222fdc251f23e98f1d96571edf7479be4cc3067b016f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
