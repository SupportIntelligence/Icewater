
rule m3ed_4f866b4980000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4f866b4980000912"
     cluster="m3ed.4f866b4980000912"
     cluster_size="79"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="microfake backdoor nitol"
     md5_hashes="['0a551e62e87fd726d6d2fa5701b33b63','0abbba68350d119d1f02a038d806ca02','3e9238040f41a6d108899a8bfaed4dbe']"

   strings:
      $hex_string = { 34c634d334eb34fd340a3510351d3523353f357b35bb35e135fd350e36143620362c3652365f3685369136a636bd36e336e83605372a372f37453767376d37b5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
