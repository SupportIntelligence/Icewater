
rule m3e9_611cb8bc0ec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611cb8bc0ec30912"
     cluster="m3e9.611cb8bc0ec30912"
     cluster_size="38"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus wbna"
     md5_hashes="['069b21222a7273be3e34659c89ebe997','537c91ad65bac8ef393f4cfd757fdad9','bb323a618c2941aac3158b07f8713699']"

   strings:
      $hex_string = { 63dffeff8d45b0508d45c0506a02e820e0feff83c40cc3c38d75d08b7d08a5a5a5a58b45088b4de064890d000000005f5e5bc9c20c00558bec83ec1868b63440 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
