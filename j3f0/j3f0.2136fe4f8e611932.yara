
rule j3f0_2136fe4f8e611932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.2136fe4f8e611932"
     cluster="j3f0.2136fe4f8e611932"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious genericrxci"
     md5_hashes="['07d874a1afe519fc339a95d5f0d87d6f','0827aa1fd8f0aa5cf4680947cbe21fd4','b76e81682db9ac935aeace11b0ec80a3']"

   strings:
      $hex_string = { e48b4d8403483c8b45f00fb740108d4401188945e88b45912b8550ffffff506a008b4584038550ffffff50e8cf07000083c40c8d45f4506a040fb645886bc028 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
