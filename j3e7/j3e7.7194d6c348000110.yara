
rule j3e7_7194d6c348000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c348000110"
     cluster="j3e7.7194d6c348000110"
     cluster_size="253"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos shedun skymobi"
     md5_hashes="['00c95b30196cec3bef90073c7aa1a3e4','040b0347db3eb54baba8de6e70d3940c','0fb504739d7fa9c8df3f954522226a57']"

   strings:
      $hex_string = { 086d436f6e7465787400136d496e697469616c4170706c69636174696f6e000e6d4c6f63616c50726f766964657200096d5061636b61676573000c6d50726f76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
