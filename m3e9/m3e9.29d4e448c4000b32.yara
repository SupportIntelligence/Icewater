
rule m3e9_29d4e448c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29d4e448c4000b32"
     cluster="m3e9.29d4e448c4000b32"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['25ff4fd8fbad85ad87ab45ab509bf61a','4c1259d0cda3f0d6c9b43b3c4983b5b2','ff446bcc86517c7c07532db0368ecdcc']"

   strings:
      $hex_string = { 5e65af057886827e3e484a4ea64330575b63af0b7d898b8a4d4b496a555138585c64af29888c8d926d313c3a53503b595d1705768f8e90948456473f0234376c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
