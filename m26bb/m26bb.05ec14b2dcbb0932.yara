
rule m26bb_05ec14b2dcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.05ec14b2dcbb0932"
     cluster="m26bb.05ec14b2dcbb0932"
     cluster_size="526"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz kryptik malicious"
     md5_hashes="['a2c26641c7621a99052bee4d614f8b14168455ad','6bbd27a91e9e625990817a9b435cd82facdbf91e','967846cffcf60cbd30dcaa63486346a5f9f97e38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.05ec14b2dcbb0932"

   strings:
      $hex_string = { 4362ebece6e924a19d3f2cc4672b209fe0baad6f978cf8b227695b9c02b38ea996a82e3700665cbf8f61fb4b3a6dbc64a26bd828c6c91bdfac9bb96c4c1d7973 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
