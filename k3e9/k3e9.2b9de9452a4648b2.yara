
rule k3e9_2b9de9452a4648b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b9de9452a4648b2"
     cluster="k3e9.2b9de9452a4648b2"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['09f34b98b05ed6e53eadcdcc199841a5','43d3e32fdba21c26f92652d49489d02b','c6c49b6f9b36e86d2749579d5861a8ed']"

   strings:
      $hex_string = { 0d0c1f22209dcd197af8d23afed56f9eb95b1c27397e62d9c598094c893365d6e0688f78b52d9991bde5c3300ee87b594de786903141a4bf5305c19c43828aad }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
