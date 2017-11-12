
rule m3e9_316338779b3b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338779b3b1112"
     cluster="m3e9.316338779b3b1112"
     cluster_size="200"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['086e4336ede32df019ab48a57b978799','0ba7e038288ad55e83e3c7d712c1e51a','727d2dd7d88b69b6971640b8431a83d2']"

   strings:
      $hex_string = { b9fb300e007782d52e751e209400df8cd806361bfa20001bfd14e18d38855800cad7c033b15ececf00cb736a34950f0dc40011a0368164b821330054e0e550b6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
